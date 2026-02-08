package v2rayxhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	dialer           N.Dialer
	tlsDialer        tls.Dialer
	serverAddr       M.Socksaddr
	requestURL       url.URL
	headers          http.Header
	host             string
	tlsConfig        tls.Config
	mode             string
	maxEachPostBytes int64
	minPostsInterval time.Duration
	maxBufferedPosts int64
	xPaddingBytesMin int
	xPaddingBytesMax int
	noGRPCHeader     bool
	noSSEHeader      bool
	httpClient       *http.Client
	httpClientOnce   sync.Once
	httpVersion      string
	isReality        bool
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (*Client, error) {
	var host string
	if len(options.Host) > 0 && options.Host[0] != "" {
		host = options.Host[0]
	} else if tlsConfig != nil && tlsConfig.ServerName() != "" {
		host = tlsConfig.ServerName()
	} else {
		host = serverAddr.String()
	}

	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = serverAddr.String()
	err := sHTTP.URLSetPath(&requestURL, options.Path)
	if err != nil {
		return nil, E.Cause(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	// Ensure path ends with "/" for Xray-core compatibility
	// Xray-core's GetNormalizedPath() always adds trailing slash
	if !strings.HasSuffix(requestURL.Path, "/") {
		requestURL.Path = requestURL.Path + "/"
	}

	headers := make(http.Header)
	for key, value := range options.Headers {
		headers[key] = value
	}

	mode := options.Mode
	if mode == "" {
		mode = "auto"
	}

	maxEachPostBytes := options.ScMaxEachPostBytes
	if maxEachPostBytes <= 0 {
		maxEachPostBytes = 1000000
	}

	minPostsIntervalMs := options.ScMinPostsIntervalMs
	if minPostsIntervalMs <= 0 {
		minPostsIntervalMs = 30
	}

	maxBufferedPosts := options.ScMaxBufferedPosts
	if maxBufferedPosts <= 0 {
		maxBufferedPosts = 30
	}

	xPaddingMin, xPaddingMax := 100, 1000
	if options.XPaddingBytes != "" {
		parts := strings.Split(options.XPaddingBytes, "-")
		if len(parts) == 2 {
			if v, err := strconv.Atoi(parts[0]); err == nil {
				xPaddingMin = v
			}
			if v, err := strconv.Atoi(parts[1]); err == nil {
				xPaddingMax = v
			}
		} else if len(parts) == 1 {
			if v, err := strconv.Atoi(parts[0]); err == nil {
				xPaddingMin = v
				xPaddingMax = v
			}
		}
	}

	var tlsDialer tls.Dialer
	var isReality bool
	if tlsConfig != nil {
		// Detect REALITY by checking if the config type contains "Reality"
		configType := reflect.TypeOf(tlsConfig).String()
		isReality = strings.Contains(configType, "Reality")
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		tlsDialer = tls.NewDialer(dialer, tlsConfig)
	}

	// Determine HTTP version
	// XHTTP requires HTTP/2 for TLS connections (including REALITY)
	// Only use HTTP/1.1 for non-TLS connections
	httpVersion := "2"
	if tlsConfig == nil {
		httpVersion = "1.1"
	}
	// Note: We ignore ALPN negotiation for version selection because:
	// 1. XHTTP protocol requires HTTP/2 over TLS
	// 2. Chrome fingerprint has ALPN ["h2", "http/1.1"] but we must use h2

	return &Client{
		dialer:           dialer,
		tlsDialer:        tlsDialer,
		serverAddr:       serverAddr,
		requestURL:       requestURL,
		headers:          headers,
		host:             host,
		tlsConfig:        tlsConfig,
		mode:             mode,
		maxEachPostBytes: maxEachPostBytes,
		minPostsInterval: time.Duration(minPostsIntervalMs) * time.Millisecond,
		maxBufferedPosts: maxBufferedPosts,
		xPaddingBytesMin: xPaddingMin,
		xPaddingBytesMax: xPaddingMax,
		noGRPCHeader:     options.NoGRPCHeader,
		noSSEHeader:      options.NoSSEHeader,
		httpVersion:      httpVersion,
		isReality:        isReality,
	}, nil
}

func (c *Client) getHTTPClient() *http.Client {
	c.httpClientOnce.Do(func() {
		var transport http.RoundTripper
		switch c.httpVersion {
		case "1.1":
			transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return c.dialConn(ctx)
				},
				ForceAttemptHTTP2:   false,
				DisableKeepAlives:   true, // Xray-core disables keep-alives for HTTP/1.1
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
			}
		case "2":
			transport = &http2.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.STDConfig) (net.Conn, error) {
					if c.tlsDialer != nil {
						return c.tlsDialer.DialTLSContext(ctx, c.serverAddr)
					}
					return c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
				},
				ReadIdleTimeout: 30 * time.Second,
			}
		default:
			transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return c.dialConn(ctx)
				},
			}
		}
		c.httpClient = &http.Client{
			Transport: transport,
			Timeout:   0,
		}
	})
	return c.httpClient
}

func (c *Client) dialConn(ctx context.Context) (net.Conn, error) {
	if c.tlsDialer != nil {
		return c.tlsDialer.DialTLSContext(ctx, c.serverAddr)
	}
	return c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	sessionID := generateSessionID()
	mode := c.mode
	if mode == "auto" {
		// Follow Xray-core mode selection:
		// - REALITY: stream-one (default)
		// - REALITY with downloadSettings: stream-up
		// - Otherwise: packet-up
		if c.isReality {
			mode = "stream-one"
		} else {
			mode = "packet-up"
		}
	}

	switch mode {
	case "packet-up":
		return c.dialPacketUp(ctx, sessionID)
	case "stream-up":
		return c.dialStreamUp(ctx, sessionID)
	case "stream-one":
		return c.dialStreamOne(ctx, sessionID)
	default:
		return c.dialPacketUp(ctx, sessionID)
	}
}

func (c *Client) dialPacketUp(ctx context.Context, sessionID string) (net.Conn, error) {
	downloadURL := c.requestURL
	downloadURL.Path = downloadURL.Path + sessionID

	padding := c.generatePadding()
	if padding != "" {
		q := downloadURL.Query()
		q.Set("x_padding", padding)
		downloadURL.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, E.Cause(err, "create download request")
	}
	c.setRequestHeaders(req, true)

	resp, err := c.getHTTPClient().Do(req)
	if err != nil {
		return nil, E.Cause(err, "download request failed")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, E.New("xhttp: unexpected status: ", resp.Status)
	}

	uploadReader, uploadWriter := io.Pipe()
	conn := &xhttpConn{
		reader:       resp.Body,
		writer:       uploadWriter,
		localAddr:    &net.TCPAddr{IP: net.IPv4zero, Port: 0},
		remoteAddr:   &net.TCPAddr{IP: net.ParseIP(c.serverAddr.AddrString()), Port: int(c.serverAddr.Port)},
		closeOnce:    sync.Once{},
		client:       c,
		sessionID:    sessionID,
		uploadReader: uploadReader,
		response:     resp,
	}

	go conn.uploadLoop(ctx)

	return conn, nil
}

func (c *Client) dialStreamUp(ctx context.Context, sessionID string) (net.Conn, error) {
	downloadURL := c.requestURL
	downloadURL.Path = downloadURL.Path + sessionID

	padding := c.generatePadding()
	if padding != "" {
		q := downloadURL.Query()
		q.Set("x_padding", padding)
		downloadURL.RawQuery = q.Encode()
	}

	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, E.Cause(err, "create download request")
	}
	c.setRequestHeaders(downloadReq, true)

	downloadResp, err := c.getHTTPClient().Do(downloadReq)
	if err != nil {
		return nil, E.Cause(err, "xhttp stream-up download request failed")
	}
	if downloadResp.StatusCode != http.StatusOK {
		downloadResp.Body.Close()
		return nil, E.New("xhttp stream-up: unexpected download status: ", downloadResp.Status)
	}

	uploadReader, uploadWriter := io.Pipe()

	uploadURL := c.requestURL
	uploadURL.Path = uploadURL.Path + sessionID
	if padding != "" {
		q := uploadURL.Query()
		q.Set("x_padding", padding)
		uploadURL.RawQuery = q.Encode()
	}

	uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL.String(), uploadReader)
	if err != nil {
		downloadResp.Body.Close()
		return nil, E.Cause(err, "create upload request")
	}
	c.setRequestHeaders(uploadReq, false)
	uploadReq.ContentLength = -1

	uploadErrChan := make(chan error, 1)
	go func() {
		resp, err := c.getHTTPClient().Do(uploadReq)
		if err != nil {
			uploadErrChan <- err
			return
		}
		resp.Body.Close()
		uploadErrChan <- nil
	}()

	return &xhttpConn{
		reader:     downloadResp.Body,
		writer:     uploadWriter,
		localAddr:  &net.TCPAddr{IP: net.IPv4zero, Port: 0},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(c.serverAddr.AddrString()), Port: int(c.serverAddr.Port)},
		closeOnce:  sync.Once{},
		response:   downloadResp,
	}, nil
}

func (c *Client) dialStreamOne(ctx context.Context, sessionID string) (net.Conn, error) {
	// For stream-one, establish TLS connection directly and create HTTP/2 client
	var conn net.Conn
	var err error
	if c.tlsDialer != nil {
		conn, err = c.tlsDialer.DialTLSContext(ctx, c.serverAddr)
	} else {
		conn, err = c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	}
	if err != nil {
		return nil, E.Cause(err, "dial TLS")
	}

	// Create HTTP/2 client connection directly (like v2rayhttp does)
	h2Transport := &http2.Transport{
		AllowHTTP:       true,
		IdleConnTimeout: 90 * time.Second,
	}
	h2Conn, err := h2Transport.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "create HTTP/2 connection")
	}

	// stream-one mode: URL path is just the normalized path (no sessionID)
	// Following Xray-core: requestURL.Path = transportConfiguration.GetNormalizedPath()
	reqURL := c.requestURL

	uploadReader, uploadWriter := io.Pipe()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL.String(), uploadReader)
	if err != nil {
		h2Conn.Close()
		return nil, E.Cause(err, "create request")
	}
	c.setRequestHeaders(req, false)
	req.ContentLength = -1

	// Set padding in Referer header (Xray-core style)
	padding := c.generatePadding()
	if padding != "" {
		refererURL := reqURL
		refererURL.RawQuery = "x_padding=" + padding
		req.Header.Set("Referer", refererURL.String())
	}

	// Create a WaitReadCloser similar to Xray-core
	waitReader := &waitReadCloser{
		wait: make(chan struct{}),
	}

	go func() {
		resp, err := h2Conn.RoundTrip(req)
		if err != nil {
			waitReader.setError(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			waitReader.setError(E.New("xhttp: unexpected status: ", resp.Status))
			return
		}
		waitReader.set(resp.Body)
	}()

	return &xhttpConn{
		reader:     waitReader,
		writer:     uploadWriter,
		localAddr:  &net.TCPAddr{IP: net.IPv4zero, Port: 0},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(c.serverAddr.AddrString()), Port: int(c.serverAddr.Port)},
		closeOnce:  sync.Once{},
	}, nil
}

// waitReadCloser waits for an io.ReadCloser to be set asynchronously
type waitReadCloser struct {
	wait   chan struct{}
	reader io.ReadCloser
	err    error
	mu     sync.Mutex
}

func (w *waitReadCloser) set(rc io.ReadCloser) {
	w.mu.Lock()
	w.reader = rc
	w.mu.Unlock()
	close(w.wait)
}

func (w *waitReadCloser) setError(err error) {
	w.mu.Lock()
	w.err = err
	w.mu.Unlock()
	close(w.wait)
}

func (w *waitReadCloser) Read(b []byte) (int, error) {
	<-w.wait
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.reader == nil {
		return 0, io.ErrClosedPipe
	}
	return w.reader.Read(b)
}

func (w *waitReadCloser) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reader != nil {
		return w.reader.Close()
	}
	return nil
}

func (c *Client) setRequestHeaders(req *http.Request, isDownload bool) {
	for key, values := range c.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Host = c.host
	req.Header.Set("Host", c.host)

	if isDownload {
		if !c.noSSEHeader {
			req.Header.Set("Accept", "text/event-stream")
		}
	} else {
		if !c.noGRPCHeader {
			req.Header.Set("Content-Type", "application/grpc")
		}
	}
}

func (c *Client) generatePadding() string {
	if c.xPaddingBytesMax <= 0 {
		return ""
	}
	length := c.xPaddingBytesMin
	if c.xPaddingBytesMax > c.xPaddingBytesMin {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(c.xPaddingBytesMax-c.xPaddingBytesMin+1)))
		if err == nil {
			length = c.xPaddingBytesMin + int(n.Int64())
		}
	}
	padding := make([]byte, length)
	for i := range padding {
		padding[i] = '0'
	}
	return string(padding)
}

func (c *Client) Close() error {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	return nil
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type xhttpConn struct {
	reader       io.ReadCloser
	writer       io.WriteCloser
	localAddr    net.Addr
	remoteAddr   net.Addr
	closeOnce    sync.Once
	client       *Client
	sessionID    string
	uploadReader *io.PipeReader
	response     *http.Response
	seqNo        atomic.Int64
}

func (c *xhttpConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *xhttpConn) Write(b []byte) (n int, err error) {
	return c.writer.Write(b)
}

func (c *xhttpConn) Close() error {
	c.closeOnce.Do(func() {
		if c.writer != nil {
			c.writer.Close()
		}
		if c.reader != nil {
			c.reader.Close()
		}
	})
	return nil
}

func (c *xhttpConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *xhttpConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *xhttpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *xhttpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *xhttpConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *xhttpConn) uploadLoop(ctx context.Context) {
	buffer := buf.NewSize(int(c.client.maxEachPostBytes))
	defer buffer.Release()

	for {
		buffer.Reset()
		n, err := buffer.ReadOnceFrom(c.uploadReader)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}

		seq := c.seqNo.Add(1) - 1
		data := buffer.Bytes()

		if err := c.postPacket(ctx, seq, data); err != nil {
			return
		}

		if c.client.minPostsInterval > 0 {
			time.Sleep(c.client.minPostsInterval)
		}
	}
}

func (c *xhttpConn) postPacket(ctx context.Context, seq int64, data []byte) error {
	uploadURL := c.client.requestURL
	uploadURL.Path = uploadURL.Path + c.sessionID + "/" + strconv.FormatInt(seq, 10)

	padding := c.client.generatePadding()
	if padding != "" {
		q := uploadURL.Query()
		q.Set("x_padding", padding)
		uploadURL.RawQuery = q.Encode()
	}

	buffer := bytes.NewReader(data)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL.String(), buffer)
	if err != nil {
		return err
	}
	c.client.setRequestHeaders(req, false)
	req.ContentLength = int64(len(data))

	resp, err := c.client.getHTTPClient().Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp: POST failed with status %d", resp.StatusCode)
	}
	return nil
}
