package v2rayxhttp

import (
	"container/heap"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

type Server struct {
	ctx                context.Context
	logger             logger.ContextLogger
	tlsConfig          tls.ServerConfig
	handler            adapter.V2RayServerTransportHandler
	httpServer         *http.Server
	h2Server           *http2.Server
	h2cHandler         http.Handler
	host               []string
	path               string
	mode               string
	noSSEHeader        bool
	scMaxEachPostBytes int
	scMaxBufferedPosts int
	localAddr          net.Addr
	sessionMu          sync.Mutex
	sessions           sync.Map
}

type serverSession struct {
	uploadQueue        *uploadQueue
	fullyConnected     chan struct{}
	fullyConnectedOnce sync.Once
}

type signal struct {
	ch   chan struct{}
	once sync.Once
}

func newSignal() *signal {
	return &signal{ch: make(chan struct{})}
}

func (s *signal) Close() {
	s.once.Do(func() { close(s.ch) })
}

func (s *signal) Wait() <-chan struct{} {
	return s.ch
}

type httpServerConn struct {
	mu     sync.Mutex
	closed bool
	done   *signal
	reader io.Reader
	http.ResponseWriter
}

func newHTTPServerConn(reader io.Reader, writer http.ResponseWriter) *httpServerConn {
	return &httpServerConn{
		done:           newSignal(),
		reader:         reader,
		ResponseWriter: writer,
	}
}

func (c *httpServerConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *httpServerConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := c.ResponseWriter.Write(p)
	if err == nil {
		c.ResponseWriter.(http.Flusher).Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.done.Close()
	return nil
}

type sessionPacket struct {
	reader  io.ReadCloser
	payload []byte
	seq     uint64
}

type uploadHeap []sessionPacket

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].seq < h[j].seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	*h = append(*h, x.(sessionPacket))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

type uploadQueue struct {
	reader        io.ReadCloser
	noMoreReader  bool
	pushedPackets chan sessionPacket
	writeCloseMu  sync.Mutex
	packetHeap    uploadHeap
	nextSeq       uint64
	closed        bool
	maxPackets    int
}

func newUploadQueue(maxPackets int) *uploadQueue {
	if maxPackets <= 0 {
		maxPackets = 30
	}
	return &uploadQueue{
		pushedPackets: make(chan sessionPacket, maxPackets),
		packetHeap:    uploadHeap{},
		maxPackets:    maxPackets,
	}
}

func (q *uploadQueue) Push(packet sessionPacket) error {
	q.writeCloseMu.Lock()
	defer q.writeCloseMu.Unlock()
	if q.closed {
		return E.New("packet queue closed")
	}
	if q.noMoreReader {
		return E.New("upload reader already exists")
	}
	if packet.reader != nil {
		q.noMoreReader = true
	}
	q.pushedPackets <- packet
	return nil
}

func (q *uploadQueue) Read(p []byte) (int, error) {
	if q.reader != nil {
		return q.reader.Read(p)
	}
	if q.closed {
		return 0, io.EOF
	}
	if len(q.packetHeap) == 0 {
		packet, ok := <-q.pushedPackets
		if !ok {
			return 0, io.EOF
		}
		if packet.reader != nil {
			q.reader = packet.reader
			return q.reader.Read(p)
		}
		heap.Push(&q.packetHeap, packet)
	}
	for len(q.packetHeap) > 0 {
		packet := heap.Pop(&q.packetHeap).(sessionPacket)
		if packet.seq == q.nextSeq {
			n := copy(p, packet.payload)
			if n < len(packet.payload) {
				packet.payload = packet.payload[n:]
				heap.Push(&q.packetHeap, packet)
			} else {
				q.nextSeq = packet.seq + 1
			}
			return n, nil
		}
		if packet.seq > q.nextSeq {
			if len(q.packetHeap) > q.maxPackets {
				return 0, E.New("packet queue is too large")
			}
			heap.Push(&q.packetHeap, packet)
			nextPacket, ok := <-q.pushedPackets
			if !ok {
				return 0, io.EOF
			}
			heap.Push(&q.packetHeap, nextPacket)
		}
	}
	return 0, nil
}

func (q *uploadQueue) Close() error {
	q.writeCloseMu.Lock()
	defer q.writeCloseMu.Unlock()
	if !q.closed {
		q.closed = true
		for {
			select {
			case packet := <-q.pushedPackets:
				if packet.reader != nil {
					q.reader = packet.reader
				}
			default:
				close(q.pushedPackets)
				goto drainDone
			}
		}
	}
drainDone:
	if q.reader != nil {
		return q.reader.Close()
	}
	return nil
}

func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayXHTTPOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	server := &Server{
		ctx:                ctx,
		logger:             logger,
		tlsConfig:          tlsConfig,
		handler:            handler,
		host:               options.Host,
		path:               normalizePath(options.Path),
		mode:               normalizeServerMode(options.Mode),
		noSSEHeader:        options.NoSSEHeader,
		scMaxEachPostBytes: int(defaultInt64(options.ScMaxEachPostBytes, 1_000_000)),
		scMaxBufferedPosts: int(defaultInt64(options.ScMaxBufferedPosts, 30)),
		h2Server:           &http2.Server{},
	}
	server.httpServer = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: C.TCPTimeout,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return log.ContextWithNewID(ctx)
		},
	}
	server.h2cHandler = h2c.NewHandler(server, server.h2Server)
	return server, nil
}

func (s *Server) Network() []string {
	return []string{N.NetworkTCP}
}

func (s *Server) Serve(listener net.Listener) error {
	s.localAddr = listener.Addr()
	if s.tlsConfig != nil {
		if len(s.tlsConfig.NextProtos()) == 0 {
			s.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		} else if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, s.tlsConfig.NextProtos()...))
		}
		listener = aTLS.NewListener(listener, s.tlsConfig)
	}
	return s.httpServer.Serve(listener)
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	return E.New("xhttp packet listener is not supported")
}

func (s *Server) Close() error {
	return common.Close(common.PtrOrNil(s.httpServer))
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "PRI" && len(request.Header) == 0 && request.URL.Path == "*" && request.Proto == "HTTP/2.0" {
		s.h2cHandler.ServeHTTP(writer, request)
		return
	}
	if !hostAllowed(request.Host, s.host) {
		s.invalidRequest(writer, request, http.StatusBadRequest, E.New("bad host: ", request.Host))
		return
	}
	if !strings.HasPrefix(request.URL.Path, s.path) {
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("bad path: ", request.URL.Path))
		return
	}
	if request.Method == http.MethodOptions {
		writer.WriteHeader(http.StatusOK)
		return
	}

	sessionID, seq := extractMetaFromPath(request.URL.Path, s.path)
	switch {
	case request.Method == http.MethodPost && sessionID == "":
		s.handleStreamOne(writer, request)
	case request.Method == http.MethodGet && sessionID != "" && seq == "":
		s.handleStreamDown(writer, request, sessionID)
	case request.Method == http.MethodPost && sessionID != "" && seq == "":
		s.handleStreamUp(writer, request, sessionID)
	case request.Method == http.MethodPost && sessionID != "" && seq != "":
		s.handlePacketUp(writer, request, sessionID, seq)
	default:
		s.invalidRequest(writer, request, http.StatusMethodNotAllowed, E.New("unsupported method: ", request.Method))
	}
}

func (s *Server) handleStreamOne(writer http.ResponseWriter, request *http.Request) {
	if s.mode != "auto" && s.mode != "stream-one" {
		s.invalidRequest(writer, request, http.StatusBadRequest, E.New("stream-one mode is not allowed"))
		return
	}
	s.prepareStreamingHeaders(writer)
	httpConn := newHTTPServerConn(request.Body, writer)
	conn := &splitConn{
		reader:     httpConn,
		writer:     httpConn,
		remoteAddr: parseRemoteAddr(request.RemoteAddr),
		localAddr:  s.localAddr,
	}
	done := make(chan struct{})
	s.handler.NewConnectionEx(request.Context(), conn, sHTTP.SourceAddress(request), M.Socksaddr{}, N.OnceClose(func(error) {
		close(done)
	}))
	select {
	case <-request.Context().Done():
	case <-done:
	case <-httpConn.done.Wait():
	}
	_ = conn.Close()
}

func (s *Server) handleStreamDown(writer http.ResponseWriter, request *http.Request, sessionID string) {
	if s.mode == "stream-one" {
		s.invalidRequest(writer, request, http.StatusBadRequest, E.New("stream-one mode is not allowed"))
		return
	}
	session := s.upsertSession(sessionID)
	session.markFullyConnected()
	defer s.deleteSession(sessionID)

	s.prepareStreamingHeaders(writer)
	httpConn := newHTTPServerConn(request.Body, writer)
	conn := &splitConn{
		reader:     session.uploadQueue,
		writer:     httpConn,
		remoteAddr: parseRemoteAddr(request.RemoteAddr),
		localAddr:  s.localAddr,
	}
	done := make(chan struct{})
	s.handler.NewConnectionEx(request.Context(), conn, sHTTP.SourceAddress(request), M.Socksaddr{}, N.OnceClose(func(error) {
		close(done)
	}))
	select {
	case <-request.Context().Done():
	case <-done:
	case <-httpConn.done.Wait():
	}
	_ = conn.Close()
}

func (s *Server) handleStreamUp(writer http.ResponseWriter, request *http.Request, sessionID string) {
	if s.mode != "auto" && s.mode != "stream-up" {
		s.invalidRequest(writer, request, http.StatusBadRequest, E.New("stream-up mode is not allowed"))
		return
	}
	session := s.upsertSession(sessionID)
	httpConn := newHTTPServerConn(request.Body, writer)
	if err := session.uploadQueue.Push(sessionPacket{reader: httpConn}); err != nil {
		_ = httpConn.Close()
		s.invalidRequest(writer, request, http.StatusConflict, err)
		return
	}
	s.prepareStreamingHeaders(writer)
	select {
	case <-request.Context().Done():
	case <-httpConn.done.Wait():
	}
	_ = httpConn.Close()
}

func (s *Server) handlePacketUp(writer http.ResponseWriter, request *http.Request, sessionID string, seq string) {
	if s.mode != "auto" && s.mode != "packet-up" {
		s.invalidRequest(writer, request, http.StatusBadRequest, E.New("packet-up mode is not allowed"))
		return
	}
	session := s.upsertSession(sessionID)
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(s.scMaxEachPostBytes)+1))
	if err != nil {
		s.invalidRequest(writer, request, http.StatusBadRequest, E.Cause(err, "read body payload"))
		return
	}
	if len(body) > s.scMaxEachPostBytes {
		s.invalidRequest(writer, request, http.StatusRequestEntityTooLarge, E.New("upload payload too large"))
		return
	}
	seqValue, err := strconv.ParseUint(seq, 10, 64)
	if err != nil {
		s.invalidRequest(writer, request, http.StatusBadRequest, E.Cause(err, "parse sequence"))
		return
	}
	if err = session.uploadQueue.Push(sessionPacket{payload: body, seq: seqValue}); err != nil {
		s.invalidRequest(writer, request, http.StatusInternalServerError, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
}

func (s *Server) prepareStreamingHeaders(writer http.ResponseWriter) {
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.Header().Set("Cache-Control", "no-store")
	if !s.noSSEHeader {
		writer.Header().Set("Content-Type", "text/event-stream")
	}
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
}

func (s *Server) upsertSession(sessionID string) *serverSession {
	if session, ok := s.sessions.Load(sessionID); ok {
		return session.(*serverSession)
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if session, ok := s.sessions.Load(sessionID); ok {
		return session.(*serverSession)
	}
	session := &serverSession{
		uploadQueue:    newUploadQueue(s.scMaxBufferedPosts),
		fullyConnected: make(chan struct{}),
	}
	s.sessions.Store(sessionID, session)
	go func() {
		select {
		case <-time.After(30 * time.Second):
			select {
			case <-session.fullyConnected:
			default:
				s.deleteSession(sessionID)
			}
		case <-session.fullyConnected:
		}
	}()
	return session
}

func (s *Server) deleteSession(sessionID string) {
	if session, ok := s.sessions.LoadAndDelete(sessionID); ok {
		_ = session.(*serverSession).uploadQueue.Close()
	}
}

func (s *serverSession) markFullyConnected() {
	s.fullyConnectedOnce.Do(func() {
		close(s.fullyConnected)
	})
}

func (s *Server) invalidRequest(writer http.ResponseWriter, request *http.Request, statusCode int, err error) {
	if statusCode > 0 {
		writer.WriteHeader(statusCode)
	}
	s.logger.ErrorContext(request.Context(), E.Cause(err, "process connection from ", request.RemoteAddr))
}

func extractMetaFromPath(requestPath string, basePath string) (string, string) {
	trimmedBase := strings.TrimRight(basePath, "/")
	trimmedPath := requestPath
	if trimmedBase != "" && strings.HasPrefix(trimmedPath, trimmedBase) {
		trimmedPath = strings.TrimPrefix(trimmedPath, trimmedBase)
	}
	trimmedPath = strings.Trim(trimmedPath, "/")
	if trimmedPath == "" {
		return "", ""
	}
	parts := strings.Split(trimmedPath, "/")
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return parts[0], ""
	default:
		return parts[0], parts[1]
	}
}

func hostAllowed(requestHost string, allowedHosts []string) bool {
	if len(allowedHosts) == 0 {
		return true
	}
	hostOnly := requestHost
	if parsedHost, _, err := net.SplitHostPort(requestHost); err == nil {
		hostOnly = parsedHost
	}
	for _, allowed := range allowedHosts {
		if strings.EqualFold(requestHost, allowed) || strings.EqualFold(hostOnly, allowed) {
			return true
		}
	}
	return false
}

func parseRemoteAddr(addr string) net.Addr {
	remoteAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return &net.TCPAddr{IP: []byte{0, 0, 0, 0}, Port: 0}
	}
	return remoteAddr
}

func normalizeServerMode(mode string) string {
	switch mode {
	case "", "auto":
		return "auto"
	case "packet-up", "stream-up", "stream-one":
		return mode
	default:
		return mode
	}
}

func defaultInt64(value int64, fallback int64) int64 {
	if value > 0 {
		return value
	}
	return fallback
}
