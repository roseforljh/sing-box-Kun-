package encryption

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"lukechampine.com/blake3"
)

type ClientInstance struct {
	NfsPKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][32]byte
	RelaysLength  int
	XorMode       uint32
	Seconds       uint32
	PaddingLens   [][3]int
	PaddingGaps   [][3]int

	RWLock sync.RWMutex
	Expire time.Time
	PfsKey []byte
	Ticket []byte
}

func (i *ClientInstance) Init(nfsPKeysBytes [][]byte, xorMode, seconds uint32, padding string) (err error) {
	if i.NfsPKeys != nil {
		return E.New("already initialized")
	}
	l := len(nfsPKeysBytes)
	if l == 0 {
		return E.New("empty nfsPKeysBytes")
	}
	i.NfsPKeys = make([]any, l)
	i.NfsPKeysBytes = nfsPKeysBytes
	i.Hash32s = make([][32]byte, l)
	for j, k := range nfsPKeysBytes {
		if len(k) == 32 {
			if i.NfsPKeys[j], err = ecdh.X25519().NewPublicKey(k); err != nil {
				return err
			}
			i.RelaysLength += 32 + 32
		} else {
			if i.NfsPKeys[j], err = mlkem.NewEncapsulationKey768(k); err != nil {
				return err
			}
			i.RelaysLength += 1088 + 32
		}
		i.Hash32s[j] = blake3.Sum256(k)
	}
	i.RelaysLength -= 32
	i.XorMode = xorMode
	i.Seconds = seconds
	return ParsePadding(padding, &i.PaddingLens, &i.PaddingGaps)
}

func (i *ClientInstance) Handshake(conn net.Conn, useAES bool) (*CommonConn, error) {
	if i.NfsPKeys == nil {
		return nil, E.New("uninitialized")
	}
	c := NewCommonConn(conn, useAES)

	ivAndRelaysLength := 16 + i.RelaysLength
	pfsKeyExchangeLength := 18 + 1184 + 32 + 16
	paddingLength, paddingLens, paddingGaps := CreatePadding(i.PaddingLens, i.PaddingGaps)
	clientHello := make([]byte, ivAndRelaysLength+pfsKeyExchangeLength+paddingLength)

	iv := clientHello[:16]
	_, _ = rand.Read(iv)
	relays := clientHello[16:ivAndRelaysLength]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.NfsPKeys {
		index := 32
		if k, ok := k.(*ecdh.PublicKey); ok {
			privateKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
			copy(relays, privateKey.PublicKey().Bytes())
			var err error
			nfsKey, err = privateKey.ECDH(k)
			if err != nil {
				return nil, err
			}
		}
		if k, ok := k.(*mlkem.EncapsulationKey768); ok {
			var ciphertext []byte
			nfsKey, ciphertext = k.Encapsulate()
			copy(relays, ciphertext)
			index = 1088
		}
		if i.XorMode > 0 {
			NewCTR(i.NfsPKeysBytes[j], iv).XORKeyStream(relays, relays[:index])
		}
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:32])
		}
		if j == len(i.NfsPKeys)-1 {
			break
		}
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays[index:], i.Hash32s[j+1][:])
		relays = relays[index+32:]
	}
	nfsAEAD := NewAEAD(iv, nfsKey, c.UseAES)

	if i.Seconds > 0 {
		i.RWLock.RLock()
		if time.Now().Before(i.Expire) {
			c.Client = i
			c.UnitedKey = append(i.PfsKey, nfsKey...)
			nfsAEAD.Seal(clientHello[:ivAndRelaysLength], nil, EncodeLength(32), nil)
			nfsAEAD.Seal(clientHello[:ivAndRelaysLength+18], nil, i.Ticket, nil)
			i.RWLock.RUnlock()
			c.PreWrite = clientHello[:ivAndRelaysLength+18+32]
			c.AEAD = NewAEAD(clientHello[ivAndRelaysLength+18:ivAndRelaysLength+18+32], c.UnitedKey, c.UseAES)
			if i.XorMode == 2 {
				c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, iv), nil, len(c.PreWrite), 16)
			}
			return c, nil
		}
		i.RWLock.RUnlock()
	}

	pfsKeyExchange := clientHello[ivAndRelaysLength : ivAndRelaysLength+pfsKeyExchangeLength]
	nfsAEAD.Seal(pfsKeyExchange[:0], nil, EncodeLength(pfsKeyExchangeLength-18), nil)
	mlkem768DKey, _ := mlkem.GenerateKey768()
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pfsPublicKey := append(mlkem768DKey.EncapsulationKey().Bytes(), x25519SKey.PublicKey().Bytes()...)
	nfsAEAD.Seal(pfsKeyExchange[:18], nil, pfsPublicKey, nil)

	padding := clientHello[ivAndRelaysLength+pfsKeyExchangeLength:]
	nfsAEAD.Seal(padding[:0], nil, EncodeLength(paddingLength-18), nil)
	nfsAEAD.Seal(padding[:18], nil, padding[18:paddingLength-16], nil)

	paddingLens[0] = ivAndRelaysLength + pfsKeyExchangeLength + paddingLens[0]
	for index, l := range paddingLens {
		if l > 0 {
			if _, err := conn.Write(clientHello[:l]); err != nil {
				return nil, err
			}
			clientHello = clientHello[l:]
		}
		if len(paddingGaps) > index {
			time.Sleep(paddingGaps[index])
		}
	}

	encryptedPfsPublicKey := make([]byte, 1088+32+16)
	if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
		return nil, err
	}
	if _, err := nfsAEAD.Open(encryptedPfsPublicKey[:0], MaxNonce, encryptedPfsPublicKey, nil); err != nil {
		return nil, err
	}
	mlkem768Key, err := mlkem768DKey.Decapsulate(encryptedPfsPublicKey[:1088])
	if err != nil {
		return nil, err
	}
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[1088 : 1088+32])
	if err != nil {
		return nil, err
	}
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, 64)
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[32:], x25519Key)
	c.UnitedKey = append(pfsKey, nfsKey...)
	c.AEAD = NewAEAD(pfsPublicKey, c.UnitedKey, c.UseAES)
	c.PeerAEAD = NewAEAD(encryptedPfsPublicKey[:1088+32], c.UnitedKey, c.UseAES)

	encryptedTicket := make([]byte, 32)
	if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
		return nil, err
	}
	if _, err := c.PeerAEAD.Open(encryptedTicket[:0], nil, encryptedTicket, nil); err != nil {
		return nil, err
	}
	seconds := DecodeLength(encryptedTicket)

	if i.Seconds > 0 && seconds > 0 {
		i.RWLock.Lock()
		i.Expire = time.Now().Add(time.Duration(seconds) * time.Second)
		i.PfsKey = pfsKey
		i.Ticket = encryptedTicket[:16]
		i.RWLock.Unlock()
	}

	encryptedLength := make([]byte, 18)
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if _, err := c.PeerAEAD.Open(encryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	length := DecodeLength(encryptedLength[:2])
	c.PeerPadding = make([]byte, length)

	if i.XorMode == 2 {
		c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, iv), NewCTR(c.UnitedKey, encryptedTicket[:16]), 0, length)
	}
	return c, nil
}
