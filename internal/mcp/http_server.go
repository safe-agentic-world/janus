package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

const downstreamHTTPSessionHeader = "MCP-Session-Id"

type DownstreamHTTPServer struct {
	base         *Server
	auth         *identity.Authenticator
	defaultAgent string
	listen       string
	sessionLimit *sessionLimiter

	server   *http.Server
	listener net.Listener

	nextID int64

	mu       sync.Mutex
	sessions map[string]*httpMCPSession
}

type httpMCPSession struct {
	id      string
	session *downstreamSession
	events  chan []byte
	closed  chan struct{}
}

func NewDownstreamHTTPServer(base *Server, auth *identity.Authenticator, listen, defaultAgent string, rateLimitPerMin int) (*DownstreamHTTPServer, error) {
	if base == nil {
		return nil, errors.New("base server is required")
	}
	if auth == nil {
		return nil, errors.New("authenticator is required")
	}
	if strings.TrimSpace(listen) == "" {
		return nil, errors.New("listen address is required")
	}
	if rateLimitPerMin <= 0 {
		rateLimitPerMin = 120
	}
	return &DownstreamHTTPServer{
		base:         base,
		auth:         auth,
		defaultAgent: strings.TrimSpace(defaultAgent),
		listen:       strings.TrimSpace(listen),
		sessionLimit: newSessionLimiter(rateLimitPerMin, time.Now),
		sessions:     map[string]*httpMCPSession{},
	}, nil
}

func (s *DownstreamHTTPServer) Addr() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *DownstreamHTTPServer) Start() error {
	if s == nil {
		return errors.New("http server is nil")
	}
	if s.server != nil {
		return errors.New("downstream mcp http server already started")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.handleMCP)
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	s.server = server
	s.listener = listener
	go func() {
		_ = server.Serve(listener)
	}()
	return nil
}

func (s *DownstreamHTTPServer) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	s.closeAllSessions()
	err := s.server.Shutdown(ctx)
	s.server = nil
	s.listener = nil
	return err
}

func (s *DownstreamHTTPServer) handleMCP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleMCPPost(w, r)
	case http.MethodGet:
		s.handleMCPStream(w, r)
	case http.MethodDelete:
		s.handleMCPDelete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *DownstreamHTTPServer) handleMCPPost(w http.ResponseWriter, r *http.Request) {
	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		s.writeHTTPError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	id, err := s.authenticate(r, body)
	if err != nil {
		s.writeHTTPError(w, http.StatusUnauthorized, "auth_error", err.Error())
		return
	}
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		s.writeRPCJSON(w, &rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	if envelope.Method == "" && hasJSONID(envelope.ID) {
		session, ok := s.requireSession(w, r, id)
		if !ok {
			return
		}
		if !s.allowSessionRequest(session.id, w) {
			return
		}
		if err := session.session.handleRPCResponse(body); err != nil {
			s.writeHTTPError(w, http.StatusBadRequest, "invalid_response", err.Error())
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var req rpcRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeRPCJSON(w, &rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	if req.Method == "initialize" {
		session := s.newSession(id)
		resp := session.session.server.handleRPCRequest(req, session.session)
		w.Header().Set(downstreamHTTPSessionHeader, session.id)
		s.writeRPCJSON(w, resp)
		return
	}
	session, ok := s.requireSession(w, r, id)
	if !ok {
		return
	}
	if !s.allowSessionRequest(session.id, w) {
		return
	}
	resp := session.session.server.handleRPCRequest(req, session.session)
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	s.writeRPCJSON(w, resp)
}

func (s *DownstreamHTTPServer) handleMCPStream(w http.ResponseWriter, r *http.Request) {
	id, err := s.authenticate(r, nil)
	if err != nil {
		s.writeHTTPError(w, http.StatusUnauthorized, "auth_error", err.Error())
		return
	}
	session, ok := s.requireSession(w, r, id)
	if !ok {
		return
	}
	if !s.allowSessionRequest(session.id, w) {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeHTTPError(w, http.StatusInternalServerError, "stream_error", "response writer does not support flushing")
		return
	}
	_, _ = io.WriteString(w, ": connected\n\n")
	flusher.Flush()
	for {
		select {
		case payload := <-session.events:
			if err := writeSSEPayload(w, payload); err != nil {
				return
			}
			flusher.Flush()
		case <-session.closed:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *DownstreamHTTPServer) handleMCPDelete(w http.ResponseWriter, r *http.Request) {
	id, err := s.authenticate(r, nil)
	if err != nil {
		s.writeHTTPError(w, http.StatusUnauthorized, "auth_error", err.Error())
		return
	}
	session, ok := s.requireSession(w, r, id)
	if !ok {
		return
	}
	if !s.allowSessionRequest(session.id, w) {
		return
	}
	s.removeSession(session.id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *DownstreamHTTPServer) authenticate(r *http.Request, body []byte) (identity.VerifiedIdentity, error) {
	if id, err := s.auth.Verify(r, body); err == nil {
		return id, nil
	}
	principal, err := s.auth.VerifyPrincipalOnly(r)
	if err != nil {
		return identity.VerifiedIdentity{}, err
	}
	agent := s.defaultAgent
	if agent == "" {
		agent = s.base.identity.Agent
	}
	return identity.VerifiedIdentity{
		Principal:   principal,
		Agent:       agent,
		Environment: s.base.identity.Environment,
	}, nil
}

func (s *DownstreamHTTPServer) requireSession(w http.ResponseWriter, r *http.Request, id identity.VerifiedIdentity) (*httpMCPSession, bool) {
	sessionID := strings.TrimSpace(r.Header.Get(downstreamHTTPSessionHeader))
	if sessionID == "" {
		s.writeHTTPError(w, http.StatusBadRequest, "invalid_session", "missing mcp session id")
		return nil, false
	}
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	s.mu.Unlock()
	if !ok {
		s.writeHTTPError(w, http.StatusBadRequest, "invalid_session", "mcp session not found")
		return nil, false
	}
	if !sameVerifiedIdentity(session.session.actionIdentity(), id) {
		s.writeHTTPError(w, http.StatusForbidden, "session_identity_mismatch", "session identity mismatch")
		return nil, false
	}
	return session, true
}

func (s *DownstreamHTTPServer) newSession(id identity.VerifiedIdentity) *httpMCPSession {
	sessionID := fmt.Sprintf("sess-%d", atomic.AddInt64(&s.nextID, 1))
	httpSession := &httpMCPSession{
		id:     sessionID,
		events: make(chan []byte, 32),
		closed: make(chan struct{}),
	}
	httpSession.session = newHTTPDownstreamSession(s.base, id, sessionID, func(data []byte) error {
		select {
		case <-httpSession.closed:
			return errUpstreamClosed
		case httpSession.events <- append([]byte(nil), data...):
			return nil
		default:
			return errors.New("downstream session event queue full")
		}
	})
	s.mu.Lock()
	s.sessions[sessionID] = httpSession
	s.mu.Unlock()
	return httpSession
}

func (s *DownstreamHTTPServer) removeSession(sessionID string) {
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	if ok {
		delete(s.sessions, sessionID)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	close(session.closed)
	session.session.closePending()
}

func (s *DownstreamHTTPServer) closeAllSessions() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.removeSession(id)
	}
}

func (s *DownstreamHTTPServer) writeHTTPError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   code,
		"message": message,
	})
}

func (s *DownstreamHTTPServer) writeRPCJSON(w http.ResponseWriter, resp *rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *DownstreamHTTPServer) allowSessionRequest(sessionID string, w http.ResponseWriter) bool {
	if s == nil || s.sessionLimit == nil || s.sessionLimit.Allow(sessionID) {
		return true
	}
	s.writeHTTPError(w, http.StatusTooManyRequests, "rate_limited", "session rate limit exceeded")
	return false
}

func writeSSEPayload(w io.Writer, payload []byte) error {
	lines := strings.Split(string(payload), "\n")
	for _, line := range lines {
		if _, err := io.WriteString(w, "data: "+line+"\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func sameVerifiedIdentity(left, right identity.VerifiedIdentity) bool {
	return left.Principal == right.Principal && left.Agent == right.Agent && left.Environment == right.Environment
}

type sessionLimiter struct {
	mu      sync.Mutex
	limit   int
	now     func() time.Time
	windows map[string]sessionRateWindow
}

type sessionRateWindow struct {
	startMinute time.Time
	count       int
}

func newSessionLimiter(limit int, now func() time.Time) *sessionLimiter {
	if now == nil {
		now = time.Now
	}
	return &sessionLimiter{
		limit:   limit,
		now:     now,
		windows: map[string]sessionRateWindow{},
	}
}

func (l *sessionLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC().Truncate(time.Minute)
	window := l.windows[key]
	if window.startMinute.IsZero() || !window.startMinute.Equal(now) {
		window = sessionRateWindow{startMinute: now}
	}
	if window.count >= l.limit {
		l.windows[key] = window
		return false
	}
	window.count++
	l.windows[key] = window
	return true
}
