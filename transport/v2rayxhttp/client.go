package v2rayxhttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	dialer             N.Dialer
	serverAddr         M.Socksaddr
	requestURL         url.URL
	requestHost        string
	headers            http.Header
	mode               string
	noGRPCHeader       bool
	scMaxEachPostBytes int
	scMinPostsInterval time.Duration
	httpClient         *http.Client
}

type splitConn struct {
	reader     io.ReadCloser
	writer     io.WriteCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
}

func (c *splitConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *splitConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	err := c.writer.Close()
	err2 := c.reader.Close()
	if err != nil {
		return err
	}
	return err2
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(time.Time) error {
	return nil
}

func (c *splitConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *splitConn) SetWriteDeadline(time.Time) error {
	return nil
}

type waitReadCloser struct {
	ready chan struct{}
	rc    io.ReadCloser
	err   error
}

func newWaitReadCloser() *waitReadCloser {
	return &waitReadCloser{ready: make(chan struct{})}
}

func (w *waitReadCloser) set(rc io.ReadCloser, err error) {
	w.rc = rc
	w.err = err
	close(w.ready)
}

func (w *waitReadCloser) Read(p []byte) (int, error) {
	<-w.ready
	if w.err != nil {
		return 0, w.err
	}
	if w.rc == nil {
		return 0, io.ErrClosedPipe
	}
	return w.rc.Read(p)
}

func (w *waitReadCloser) Close() error {
	<-w.ready
	if w.rc != nil {
		return w.rc.Close()
	}
	return nil
}

type packetWriter struct {
	client    *Client
	ctx       context.Context
	sessionID string
	seq       atomic.Int64
	closed    atomic.Bool
	writeMu   sync.Mutex
}

func (w *packetWriter) Close() error {
	w.closed.Store(true)
	return nil
}

func (w *packetWriter) Write(p []byte) (int, error) {
	if w.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	chunkSize := w.client.scMaxEachPostBytes
	if chunkSize <= 0 {
		chunkSize = 1_000_000
	}
	written := 0
	for start := 0; start < len(p); start += chunkSize {
		end := start + chunkSize
		if end > len(p) {
			end = len(p)
		}
		if written > 0 && w.client.scMinPostsInterval > 0 {
			time.Sleep(w.client.scMinPostsInterval)
		}
		seq := strconv.FormatInt(w.seq.Add(1)-1, 10)
		err := w.client.postPacket(w.ctx, w.sessionID, seq, p[start:end])
		if err != nil {
			return written, err
		}
		written += end - start
	}
	return written, nil
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	requestHost := firstNonEmpty(firstListValue(options.Host), tlsServerName(tlsConfig), serverAddr.AddrString())
	requestURL, err := buildRequestURL(serverAddr, requestHost, options.Path, tlsConfig != nil)
	if err != nil {
		return nil, err
	}
	client, err := buildHTTPClient(dialer, serverAddr, tlsConfig)
	if err != nil {
		return nil, err
	}
	mode := normalizeMode(options.Mode, tlsConfig != nil)
	maxEachPostBytes := int(options.ScMaxEachPostBytes)
	if maxEachPostBytes <= 0 {
		maxEachPostBytes = 1_000_000
	}
	minPostsInterval := time.Duration(options.ScMinPostsIntervalMs) * time.Millisecond
	if minPostsInterval <= 0 {
		minPostsInterval = 30 * time.Millisecond
	}
	return &Client{
		dialer:             dialer,
		serverAddr:         serverAddr,
		requestURL:         requestURL,
		requestHost:        requestHost,
		headers:            options.Headers.Build(),
		mode:               mode,
		noGRPCHeader:       options.NoGRPCHeader,
		scMaxEachPostBytes: maxEachPostBytes,
		scMinPostsInterval: minPostsInterval,
		httpClient:         client,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	switch c.mode {
	case "stream-one":
		return c.dialStreamOne(ctx)
	case "stream-up":
		return c.dialSplitStream(ctx)
	case "packet-up":
		return c.dialPacketUp(ctx)
	default:
		return nil, E.New("unsupported xhttp mode: ", c.mode)
	}
}

func (c *Client) Close() error {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

func (c *Client) dialStreamOne(ctx context.Context) (net.Conn, error) {
	sessionID := ""
	bodyReader, bodyWriter := io.Pipe()
	reader, remoteAddr, localAddr, err := c.openStream(ctx, sessionID, "", bodyReader, false)
	if err != nil {
		bodyWriter.Close()
		return nil, err
	}
	return &splitConn{
		reader:     reader,
		writer:     bodyWriter,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}, nil
}

func (c *Client) dialSplitStream(ctx context.Context) (net.Conn, error) {
	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}
	downloadReader, remoteAddr, localAddr, err := c.openStream(ctx, sessionID, "", nil, false)
	if err != nil {
		return nil, err
	}
	bodyReader, bodyWriter := io.Pipe()
	if _, _, _, err = c.openStream(ctx, sessionID, "", bodyReader, true); err != nil {
		bodyWriter.Close()
		downloadReader.Close()
		return nil, err
	}
	return &splitConn{
		reader:     downloadReader,
		writer:     bodyWriter,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}, nil
}

func (c *Client) dialPacketUp(ctx context.Context) (net.Conn, error) {
	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}
	reader, remoteAddr, localAddr, err := c.openStream(ctx, sessionID, "", nil, false)
	if err != nil {
		return nil, err
	}
	return &splitConn{
		reader:     reader,
		writer:     &packetWriter{client: c, ctx: ctx, sessionID: sessionID},
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}, nil
}

func (c *Client) openStream(ctx context.Context, sessionID string, seq string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	waiter := newWaitReadCloser()
	var remoteAddr net.Addr
	var localAddr net.Addr
	gotConn := make(chan struct{})
	var gotConnOnce sync.Once
	traceCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			remoteAddr = info.Conn.RemoteAddr()
			localAddr = info.Conn.LocalAddr()
			gotConnOnce.Do(func() {
				close(gotConn)
			})
		},
	})
	req, err := http.NewRequestWithContext(traceCtx, methodForStream(body), c.requestURL.String(), body)
	if err != nil {
		return nil, nil, nil, err
	}
	c.fillRequest(req, sessionID, seq)
	go func() {
		resp, reqErr := c.httpClient.Do(req)
		if reqErr != nil {
			gotConnOnce.Do(func() {
				close(gotConn)
			})
			waiter.set(nil, reqErr)
			return
		}
		if resp.StatusCode != http.StatusOK {
			err = E.New("xhttp: unexpected status: ", resp.Status)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			gotConnOnce.Do(func() {
				close(gotConn)
			})
			waiter.set(nil, err)
			return
		}
		if uploadOnly {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			gotConnOnce.Do(func() {
				close(gotConn)
			})
			waiter.set(nil, io.ErrClosedPipe)
			return
		}
		waiter.set(resp.Body, nil)
	}()
	<-gotConn
	return waiter, remoteAddr, localAddr, nil
}

func (c *Client) postPacket(ctx context.Context, sessionID string, seq string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.requestURL.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	c.fillRequest(req, sessionID, seq)
	req.ContentLength = int64(len(payload))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return E.New("xhttp: POST failed with status ", resp.StatusCode)
	}
	return nil
}

func (c *Client) fillRequest(req *http.Request, sessionID string, seq string) {
	req.Header = c.headers.Clone()
	req.Host = c.requestHost
	path := c.requestURL.Path
	if sessionID != "" {
		path = appendPathSegment(path, sessionID)
	}
	if seq != "" {
		path = appendPathSegment(path, seq)
	}
	req.URL.Path = path
	applyDefaultXPadding(req)
	if req.Body != nil && !c.noGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}
}

func applyDefaultXPadding(req *http.Request) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	paddingURL := *req.URL
	query := paddingURL.Query()
	query.Set("x_padding", strings.Repeat("X", 100))
	paddingURL.RawQuery = query.Encode()
	req.Header.Set("Referer", paddingURL.String())
}

func buildHTTPClient(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig tls.Config) (*http.Client, error) {
	if tlsConfig == nil {
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, serverAddr)
				},
				DisableKeepAlives: true,
			},
		}, nil
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
	}
	tlsDialer := tls.NewDialer(dialer, tlsConfig)
	if onlyHTTP11(tlsConfig.NextProtos()) {
		return &http.Client{
			Transport: &http.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tlsDialer.DialTLSContext(ctx, serverAddr)
				},
				DisableKeepAlives: true,
			},
		}, nil
	}
	return &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.STDConfig) (net.Conn, error) {
				return tlsDialer.DialTLSContext(ctx, serverAddr)
			},
		},
	}, nil
}

func buildRequestURL(serverAddr M.Socksaddr, requestHost string, path string, useTLS bool) (url.URL, error) {
	var requestURL url.URL
	if useTLS {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = requestHost
	if requestURL.Host == "" {
		requestURL.Host = serverAddr.AddrString()
	}
	err := sHTTP.URLSetPath(&requestURL, normalizePath(path))
	if err != nil {
		return url.URL{}, E.Cause(err, "parse path")
	}
	requestURL.Path = normalizePath(requestURL.Path)
	return requestURL, nil
}

func normalizePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	if !strings.HasSuffix(trimmed, "/") {
		trimmed += "/"
	}
	return trimmed
}

func appendPathSegment(base string, segment string) string {
	trimmedBase := strings.TrimRight(base, "/")
	trimmedSegment := strings.Trim(strings.TrimSpace(segment), "/")
	if trimmedSegment == "" {
		if trimmedBase == "" {
			return "/"
		}
		return trimmedBase + "/"
	}
	return trimmedBase + "/" + trimmedSegment
}

func methodForStream(body io.Reader) string {
	if body == nil {
		return http.MethodGet
	}
	return http.MethodPost
}

func normalizeMode(mode string, tlsEnabled bool) string {
	switch mode {
	case "", "auto":
		if tlsEnabled {
			return "stream-one"
		}
		return "packet-up"
	case "packet-up", "stream-up", "stream-one":
		return mode
	default:
		return mode
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstListValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func tlsServerName(config tls.Config) string {
	if config == nil {
		return ""
	}
	return config.ServerName()
}

func onlyHTTP11(nextProtos []string) bool {
	return len(nextProtos) == 1 && nextProtos[0] == "http/1.1"
}

func newSessionID() (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("new xhttp session id: %w", err)
	}
	return id.String(), nil
}
