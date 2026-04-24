package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/version"
)

type downstreamSession struct {
	server   *Server
	identity identity.VerifiedIdentity
	reader   *bufio.Reader
	writer   *bufio.Writer

	modeMu  sync.Mutex
	mode    stdioMode
	modeSet bool

	writeMu sync.Mutex

	mu         sync.Mutex
	pending    map[string]chan rpcMessage
	closed     bool
	sessionID  string
	transport  string
	sendRawRPC func([]byte) error

	nextID int64
	done   chan struct{}

	clientSampling bool
}

func newDownstreamSession(server *Server, in io.Reader, out io.Writer) *downstreamSession {
	return &downstreamSession{
		server:    server,
		identity:  server.identity,
		reader:    bufio.NewReader(in),
		writer:    bufio.NewWriter(out),
		pending:   map[string]chan rpcMessage{},
		done:      make(chan struct{}),
		transport: "stdio",
	}
}

func newHTTPDownstreamSession(server *Server, id identity.VerifiedIdentity, sessionID string, sendRaw func([]byte) error) *downstreamSession {
	return &downstreamSession{
		server:     server.CloneForIdentity(id),
		identity:   id,
		pending:    map[string]chan rpcMessage{},
		done:       make(chan struct{}),
		sessionID:  sessionID,
		transport:  "streamable_http",
		sendRawRPC: sendRaw,
	}
}

func (s *downstreamSession) serve() error {
	defer close(s.done)
	defer s.writer.Flush()
	s.server.logger.ReadyBanner(s.server.identity.Environment, s.server.policyBundleHash, s.server.policyBundleSources, version.Current().Version, s.server.pid)
	for {
		payload, mode, err := readStdioPayload(s.reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.closePending()
				return nil
			}
			s.closePending()
			s.server.logger.Error("mcp stdio read failure: " + err.Error())
			return err
		}
		s.setMode(mode)
		if mode == stdioModeLine && !isRPCPayload(payload) {
			resp := s.server.handleLegacyLine(payload)
			if err := s.writeLegacyResponse(resp); err != nil {
				s.closePending()
				s.server.logger.Error("mcp stdio line write failure: " + err.Error())
				return err
			}
			continue
		}
		if err := s.dispatchRPCPayload(payload); err != nil {
			s.closePending()
			s.server.logger.Error("mcp stdio rpc dispatch failure: " + err.Error())
			return err
		}
	}
}

func (s *downstreamSession) dispatchRPCPayload(payload []byte) error {
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return s.writeRPCResponse(&rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
	}
	if envelope.Method == "" && hasJSONID(envelope.ID) {
		return s.handleRPCResponse(payload)
	}
	var req rpcRequest
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return s.writeRPCResponse(&rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
	}
	resp := s.server.handleRPCRequest(req, s)
	if resp == nil {
		return nil
	}
	return s.writeRPCResponse(resp)
}

func (s *downstreamSession) handleRPCResponse(payload []byte) error {
	var resp rpcResponse
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		return fmt.Errorf("invalid downstream response: %w", err)
	}
	idKey := rpcIDKey(resp.ID)
	s.mu.Lock()
	ch, ok := s.pending[idKey]
	if ok {
		delete(s.pending, idKey)
	}
	s.mu.Unlock()
	if ok {
		ch <- rpcMessage{resp: &resp}
	}
	return nil
}

func (s *downstreamSession) sendRequest(method string, params map[string]any) (*rpcResponse, error) {
	id := fmt.Sprintf("nomos-%d", atomic.AddInt64(&s.nextID, 1))
	ch := make(chan rpcMessage, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errUpstreamClosed
	}
	s.pending[id] = ch
	s.mu.Unlock()

	// Encode as a real JSON-RPC request on the wire.
	wire := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
	data, err := json.Marshal(wire)
	if err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, err
	}
	if err := s.writeRawRPC(data); err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, err
	}
	select {
	case msg := <-ch:
		if msg.err != nil {
			return nil, msg.err
		}
		return msg.resp, nil
	case <-s.done:
		return nil, errUpstreamUnavailable
	}
}

func (s *downstreamSession) writeLegacyResponse(resp Response) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeJSONLine(s.writer, resp)
}

func (s *downstreamSession) writeRPCResponse(resp *rpcResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return s.writeRawRPC(data)
}

func (s *downstreamSession) writeRawRPC(data []byte) error {
	if s.sendRawRPC != nil {
		return s.sendRawRPC(data)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	mode, _ := s.currentMode()
	if mode == stdioModeFramed {
		_, err := fmt.Fprintf(s.writer, "Content-Length: %d\r\n\r\n", len(data))
		if err != nil {
			return err
		}
		if _, err := s.writer.Write(data); err != nil {
			return err
		}
		return s.writer.Flush()
	}
	if _, err := s.writer.Write(data); err != nil {
		return err
	}
	if err := s.writer.WriteByte('\n'); err != nil {
		return err
	}
	return s.writer.Flush()
}

func (s *downstreamSession) actionIdentity() identity.VerifiedIdentity {
	if s == nil {
		return identity.VerifiedIdentity{}
	}
	return s.identity
}

func (s *downstreamSession) auditMetadata() map[string]any {
	if s == nil {
		return nil
	}
	metadata := map[string]any{
		"downstream_transport": s.transport,
	}
	if s.sessionID != "" {
		metadata["downstream_session_id"] = s.sessionID
	}
	return metadata
}

func (s *downstreamSession) setMode(mode stdioMode) {
	s.modeMu.Lock()
	defer s.modeMu.Unlock()
	if !s.modeSet {
		s.mode = mode
		s.modeSet = true
	}
}

func (s *downstreamSession) currentMode() (stdioMode, bool) {
	s.modeMu.Lock()
	defer s.modeMu.Unlock()
	return s.mode, s.modeSet
}

func (s *downstreamSession) closePending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, ch := range s.pending {
		ch <- rpcMessage{err: errUpstreamUnavailable}
	}
	s.pending = map[string]chan rpcMessage{}
}
