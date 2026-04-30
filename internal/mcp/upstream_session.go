package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

var (
	errUpstreamClosed                = errors.New("upstream mcp session closed")
	errUpstreamUnavailable           = errors.New("upstream mcp session unavailable")
	errUpstreamTimeout               = errors.New("UPSTREAM_TIMEOUT")
	errUpstreamCanceled              = errors.New("UPSTREAM_CANCELED")
	errUpstreamCredentialUnavailable = errors.New("UPSTREAM_CREDENTIAL_UNAVAILABLE")
)

const (
	defaultUpstreamInitializeTimeout = 5 * time.Second
	defaultUpstreamEnumerateTimeout  = 5 * time.Second
	defaultUpstreamCallTimeout       = 30 * time.Second
	defaultUpstreamStreamTimeout     = 30 * time.Second
)

type upstreamTransport interface {
	callMethod(ctx context.Context, timeout time.Duration, method string, params map[string]any) (any, error)
	setRequestHandler(handler upstreamRequestHandler)
	isClosed() bool
	close()
	doneCh() <-chan struct{}
	envShapeHash() string
}

type upstreamRequestHandler func(req rpcRequest) *rpcResponse

func upstreamCallContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return ctx, func() {}
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining <= timeout {
			return ctx, func() {}
		}
	}
	return context.WithTimeout(ctx, timeout)
}

func startUpstreamTransport(config UpstreamServerConfig, notify func(method string, params json.RawMessage)) (upstreamTransport, error) {
	switch strings.TrimSpace(config.Transport) {
	case "stdio":
		return startUpstreamConn(config, notify)
	case "streamable_http":
		return startUpstreamHTTPConn(config, notify, false)
	case "sse":
		return startUpstreamHTTPConn(config, notify, true)
	default:
		return nil, fmt.Errorf("unsupported upstream mcp transport %q", config.Transport)
	}
}

const (
	defaultUpstreamBackoffInitial = 100 * time.Millisecond
	defaultUpstreamBackoffMax     = 5 * time.Second
	maxUpstreamStderrRetain       = 8 * 1024
	upstreamNotifyBufferSize      = 16
)

type rpcMessage struct {
	resp *rpcResponse
	err  error
}

type upstreamConn struct {
	config            UpstreamServerConfig
	cmd               *exec.Cmd
	stdin             io.WriteCloser
	stdout            io.ReadCloser
	stderr            io.ReadCloser
	writer            *bufio.Writer
	notifyFn          func(method string, params json.RawMessage)
	envShapeHashValue string

	done       chan struct{}
	stderrDone chan struct{}

	writeMu sync.Mutex

	mu             sync.Mutex
	pending        map[string]chan rpcMessage
	nextID         int64
	closed         bool
	err            error
	requestHandler upstreamRequestHandler

	stderrMu  sync.Mutex
	stderrBuf bytes.Buffer
}

func (c *upstreamConn) doneCh() <-chan struct{} { return c.done }

func (c *upstreamConn) envShapeHash() string { return c.envShapeHashValue }

func (c *upstreamConn) setRequestHandler(handler upstreamRequestHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestHandler = handler
}

func startUpstreamConn(config UpstreamServerConfig, notify func(method string, params json.RawMessage)) (*upstreamConn, error) {
	cmd := exec.Command(config.Command, config.Args...)
	if strings.TrimSpace(config.Workdir) != "" {
		cmd.Dir = config.Workdir
	}
	env, envShapeHash := buildUpstreamEnvironment(config)
	cmd.Env = env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, err
	}
	conn := &upstreamConn{
		config:            config,
		cmd:               cmd,
		stdin:             stdin,
		stdout:            stdout,
		stderr:            stderr,
		writer:            bufio.NewWriter(stdin),
		pending:           map[string]chan rpcMessage{},
		done:              make(chan struct{}),
		stderrDone:        make(chan struct{}),
		notifyFn:          notify,
		envShapeHashValue: envShapeHash,
	}
	go conn.drainStderr()
	go conn.readLoop()

	if err := conn.handshake(); err != nil {
		snapshot := conn.stderrSnapshot()
		conn.close()
		return nil, upstreamStageError(config, "initialize", err, snapshot)
	}
	return conn, nil
}

func (c *upstreamConn) drainStderr() {
	defer close(c.stderrDone)
	if c.stderr == nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.stderr.Read(buf)
		if n > 0 {
			c.stderrMu.Lock()
			c.stderrBuf.Write(buf[:n])
			if c.stderrBuf.Len() > maxUpstreamStderrRetain {
				trimmed := make([]byte, maxUpstreamStderrRetain)
				src := c.stderrBuf.Bytes()
				copy(trimmed, src[len(src)-maxUpstreamStderrRetain:])
				c.stderrBuf.Reset()
				c.stderrBuf.Write(trimmed)
			}
			c.stderrMu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (c *upstreamConn) stderrSnapshot() string {
	c.stderrMu.Lock()
	defer c.stderrMu.Unlock()
	return strings.TrimSpace(c.stderrBuf.String())
}

func (c *upstreamConn) readLoop() {
	defer close(c.done)
	reader := bufio.NewReader(c.stdout)
	for {
		body, err := readMCPPayload(reader)
		if err != nil {
			c.terminate(err)
			return
		}
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) == 0 {
			continue
		}
		if err := c.dispatch(trimmed); err != nil {
			c.terminate(err)
			return
		}
	}
}

func (c *upstreamConn) dispatch(body []byte) error {
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("invalid upstream payload: %w", err)
	}
	if envelope.Method != "" {
		if !hasJSONID(envelope.ID) {
			if c.notifyFn != nil {
				var note struct {
					Params json.RawMessage `json:"params"`
				}
				if err := json.Unmarshal(body, &note); err == nil {
					c.notifyFn(envelope.Method, note.Params)
				} else {
					c.notifyFn(envelope.Method, nil)
				}
			}
			return nil
		}
		return c.handleServerRequest(body)
	}
	var resp rpcResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		return fmt.Errorf("invalid upstream response: %w", err)
	}
	idKey := rpcIDKey(resp.ID)
	c.mu.Lock()
	ch, ok := c.pending[idKey]
	if ok {
		delete(c.pending, idKey)
	}
	c.mu.Unlock()
	if ok {
		ch <- rpcMessage{resp: &resp}
	}
	return nil
}

func (c *upstreamConn) handleServerRequest(body []byte) error {
	var req rpcRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("invalid upstream request: %w", err)
	}
	c.mu.Lock()
	handler := c.requestHandler
	c.mu.Unlock()
	resp := &rpcResponse{
		JSONRPC: "2.0",
		ID:      parseRPCID(req.ID),
		Error:   &rpcError{Code: -32601, Message: "method not found"},
	}
	if handler != nil {
		if handled := handler(req); handled != nil {
			resp = handled
			resp.JSONRPC = "2.0"
			if resp.ID == nil {
				resp.ID = parseRPCID(req.ID)
			}
		}
	}
	c.writeMu.Lock()
	err := writeUpstreamRPCResponse(c.writer, resp)
	c.writeMu.Unlock()
	return err
}

func (c *upstreamConn) terminate(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if c.err == nil {
		c.err = err
	}
	pending := c.pending
	c.pending = map[string]chan rpcMessage{}
	c.mu.Unlock()
	for _, ch := range pending {
		ch <- rpcMessage{err: errUpstreamUnavailable}
	}
}

func (c *upstreamConn) handshake() error {
	if _, err := c.sendRequest(context.Background(), c.timeoutOrDefault(c.config.InitializeTimeout, defaultUpstreamInitializeTimeout), "initialize", "initialize", map[string]any{
		"protocolVersion": SupportedProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "nomos-upstream-gateway",
			"version": "v1",
		},
	}); err != nil {
		return err
	}
	return c.sendNotification("notifications/initialized", map[string]any{})
}

func (c *upstreamConn) sendRequest(ctx context.Context, timeout time.Duration, id, method string, params map[string]any) (*rpcResponse, error) {
	ctx, cancel := upstreamCallContext(ctx, timeout)
	defer cancel()
	ch := make(chan rpcMessage, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errUpstreamUnavailable
	}
	if _, exists := c.pending[id]; exists {
		c.mu.Unlock()
		return nil, fmt.Errorf("upstream mcp session id collision %q", id)
	}
	c.pending[id] = ch
	c.mu.Unlock()

	c.writeMu.Lock()
	err := writeUpstreamRPCRequest(c.writer, method, id, params)
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		c.terminate(err)
		return nil, errUpstreamUnavailable
	}
	select {
	case msg := <-ch:
		if msg.err != nil {
			return nil, msg.err
		}
		if msg.resp != nil && msg.resp.Error != nil {
			return msg.resp, newUpstreamApplicationError(msg.resp.Error)
		}
		return msg.resp, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errUpstreamTimeout
		}
		return nil, errUpstreamCanceled
	case <-c.done:
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, errUpstreamUnavailable
	}
}

func (c *upstreamConn) sendNotification(method string, params map[string]any) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errUpstreamUnavailable
	}
	c.writeMu.Lock()
	err := writeUpstreamRPCNotification(c.writer, method, params)
	c.writeMu.Unlock()
	return err
}

func (c *upstreamConn) allocateRequestID() string {
	id := atomic.AddInt64(&c.nextID, 1)
	return "req-" + strconv.FormatInt(id, 10)
}

func (c *upstreamConn) callMethod(ctx context.Context, timeout time.Duration, method string, params map[string]any) (any, error) {
	ctx, cancel := upstreamCallContext(ctx, timeout)
	defer cancel()
	id := c.allocateRequestID()
	resp, err := c.sendRequest(ctx, timeout, id, method, params)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errUpstreamUnavailable
	}
	return resp.Result, nil
}

func (c *upstreamConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *upstreamConn) close() {
	c.terminate(errUpstreamClosed)
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	_ = c.stdin.Close()
	<-c.done
	<-c.stderrDone
	if c.cmd != nil {
		_ = c.cmd.Wait()
	}
}

func (c *upstreamConn) timeoutOrDefault(timeout, fallback time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return fallback
}

type upstreamSession struct {
	config         UpstreamServerConfig
	id             string
	logger         *runtimeLogger
	onNotification func(config UpstreamServerConfig, method string, params json.RawMessage)
	breaker        *upstreamBreaker
	credentials    *upstreamCredentialManager
	emitter        *telemetry.Emitter

	mu                sync.Mutex
	callMu            sync.Mutex
	conn              upstreamTransport
	starting          bool
	closed            bool
	lastFailureAt     time.Time
	attempts          int
	envShapeHashValue string
	backoffInitial    time.Duration
	backoffMax        time.Duration
	clock             func() time.Time
}

func newUpstreamSession(config UpstreamServerConfig, logger *runtimeLogger, notifyFn func(UpstreamServerConfig, string, json.RawMessage), clock func() time.Time, emitter *telemetry.Emitter, id identity.VerifiedIdentity, credentialBroker UpstreamCredentialBroker, recorder audit.Recorder) *upstreamSession {
	if clock == nil {
		clock = time.Now
	}
	session := &upstreamSession{
		config:         config,
		id:             nextUpstreamSessionID(config.Name),
		logger:         logger,
		onNotification: notifyFn,
		breaker:        newUpstreamBreaker(config.Name, config.breakerConfig(), clock, emitter),
		credentials:    newUpstreamCredentialManager(config, id, credentialBroker, recorder, clock),
		emitter:        emitter,
		clock:          clock,
		backoffInitial: defaultUpstreamBackoffInitial,
		backoffMax:     defaultUpstreamBackoffMax,
	}
	emitUpstreamLifecycleObservability(session.emitter, session.logger, session.config, session.id, "created", "success", nil)
	return session
}

func (s *upstreamSession) connForTest() *upstreamConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if conn, ok := s.conn.(*upstreamConn); ok {
		return conn
	}
	return nil
}

func (s *upstreamSession) envShapeHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.envShapeHashValue
}

func (s *upstreamSession) breakerSnapshot() upstreamBreakerSnapshot {
	if s == nil || s.breaker == nil {
		return upstreamBreakerSnapshot{State: upstreamBreakerDisabled}
	}
	return s.breaker.snapshot()
}

func (s *upstreamSession) transportForTest() upstreamTransport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *upstreamSession) setBackoffForTest(initial, max time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if initial < 0 {
		initial = 0
	}
	if max < initial {
		max = initial
	}
	s.backoffInitial = initial
	s.backoffMax = max
}

func (s *upstreamSession) backoffElapsedLocked() bool {
	if s.attempts == 0 || s.lastFailureAt.IsZero() || s.backoffInitial == 0 {
		return true
	}
	wait := s.backoffInitial
	for i := 1; i < s.attempts; i++ {
		wait *= 2
		if wait >= s.backoffMax {
			wait = s.backoffMax
			break
		}
	}
	return s.clock().Sub(s.lastFailureAt) >= wait
}

func (s *upstreamSession) ensureConn(material upstreamCredentialMaterial) (upstreamTransport, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errUpstreamClosed
	}
	if s.conn != nil {
		select {
		case <-s.conn.doneCh():
			s.conn = nil
		default:
			conn := s.conn
			s.mu.Unlock()
			return conn, nil
		}
	}
	if s.starting {
		s.mu.Unlock()
		return nil, errUpstreamUnavailable
	}
	if !s.backoffElapsedLocked() {
		s.mu.Unlock()
		return nil, errUpstreamUnavailable
	}
	if s.logger != nil && s.config.Transport == "stdio" && len(uniqueSortedNames(s.config.EnvAllowlist)) == 0 && len(s.config.Env) == 0 {
		message := fmt.Sprintf("upstream mcp server %q uses empty env by default", s.config.Name)
		if !isAbsoluteCommandPath(s.config.Command) {
			message = fmt.Sprintf("%s and non-absolute command %q", message, strings.TrimSpace(s.config.Command))
		}
		s.logger.Warn(message + "; set env_allowlist/env explicitly or use an absolute command path")
	}
	s.starting = true
	s.mu.Unlock()

	startConfig := upstreamConfigWithCredentialMaterial(s.config, material)
	connectStarted := s.clock()
	conn, startErr := startUpstreamTransport(startConfig, func(method string, params json.RawMessage) {
		if s.onNotification != nil {
			s.onNotification(s.config, method, params)
		}
	})
	connectElapsed := s.clock().Sub(connectStarted)

	s.mu.Lock()
	s.starting = false
	if s.closed {
		if conn != nil {
			go conn.close()
		}
		s.mu.Unlock()
		emitUpstreamLifecycleObservability(s.emitter, s.logger, s.config, s.id, "connect", "error", errUpstreamClosed)
		return nil, errUpstreamClosed
	}
	if startErr != nil {
		s.attempts++
		s.lastFailureAt = s.clock()
		s.mu.Unlock()
		emitUpstreamLifecycleObservability(s.emitter, s.logger, s.config, s.id, "connect", "error", startErr)
		emitUpstreamRequestObservability(s.emitter, s.logger, s.config, s.id, "initialize", connectElapsed, startErr)
		return nil, startErr
	}
	s.conn = conn
	s.envShapeHashValue = conn.envShapeHash()
	s.attempts = 0
	s.lastFailureAt = time.Time{}
	s.mu.Unlock()
	emitUpstreamLifecycleObservability(s.emitter, s.logger, s.config, s.id, "connect", "success", nil)
	emitUpstreamRequestObservability(s.emitter, s.logger, s.config, s.id, "initialize", connectElapsed, nil)
	return conn, nil
}

func (s *upstreamSession) call(ctx context.Context, method string, params map[string]any) (any, error) {
	return s.callWithRequests(ctx, method, params, nil)
}

func (s *upstreamSession) callWithRequests(ctx context.Context, method string, params map[string]any, handler upstreamRequestHandler) (any, error) {
	started := s.clock()
	permit, err := s.breaker.beforeCall()
	if err != nil {
		emitUpstreamRequestObservability(s.emitter, s.logger, s.config, s.id, method, s.clock().Sub(started), err)
		return nil, err
	}
	s.callMu.Lock()
	defer s.callMu.Unlock()
	material, refreshed, err := s.ensureCredentialMaterial()
	if err != nil {
		s.breaker.forceOpen(upstreamFailureCredential)
		emitUpstreamRequestObservability(s.emitter, s.logger, s.config, s.id, method, s.clock().Sub(started), err)
		return nil, err
	}
	s.applyCredentialRefresh(material, refreshed)
	conn, err := s.ensureConn(material)
	if err != nil {
		s.breaker.afterCall(permit, err)
		emitUpstreamRequestObservability(s.emitter, s.logger, s.config, s.id, method, s.clock().Sub(started), err)
		return nil, err
	}
	conn.setRequestHandler(handler)
	defer conn.setRequestHandler(nil)
	result, callErr := conn.callMethod(ctx, s.timeoutForMethod(ctx, method), method, params)
	s.breaker.afterCall(permit, callErr)
	emitUpstreamRequestObservability(s.emitter, s.logger, s.config, s.id, method, s.clock().Sub(started), callErr)
	if callErr == nil {
		return result, nil
	}
	if conn.isClosed() {
		s.mu.Lock()
		if s.conn == conn {
			s.conn = nil
		}
		s.mu.Unlock()
	}
	return nil, callErr
}

func (s *upstreamSession) ensureCredentialMaterial() (upstreamCredentialMaterial, bool, error) {
	if s.credentials == nil {
		return upstreamCredentialMaterial{}, false, nil
	}
	return s.credentials.ensure()
}

func (s *upstreamSession) applyCredentialRefresh(material upstreamCredentialMaterial, refreshed bool) {
	if !refreshed {
		return
	}
	s.mu.Lock()
	conn := s.conn
	if conn == nil {
		s.mu.Unlock()
		return
	}
	if updater, ok := conn.(interface{ setCredentialHeaders(map[string]string) }); ok {
		updater.setCredentialHeaders(material.Headers)
		s.mu.Unlock()
		return
	}
	if !material.RestartOnRefresh {
		s.mu.Unlock()
		return
	}
	s.conn = nil
	s.mu.Unlock()
	conn.close()
}

func (s *upstreamSession) timeoutForMethod(ctx context.Context, method string) time.Duration {
	stageTimeout := s.config.CallTimeout
	switch method {
	case "initialize":
		stageTimeout = s.config.InitializeTimeout
	case "tools/list", "resources/list", "prompts/list":
		stageTimeout = s.config.EnumerateTimeout
	}
	return s.timeoutOrDefault(ctx, stageTimeout, defaultUpstreamCallTimeout)
}

func (s *upstreamSession) timeoutOrDefault(ctx context.Context, timeout, fallback time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining > 0 {
				return remaining
			}
		}
	}
	return fallback
}

func (s *upstreamSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn != nil {
		conn.close()
	}
	if s.credentials != nil {
		s.credentials.close()
	}
	emitUpstreamLifecycleObservability(s.emitter, s.logger, s.config, s.id, "closed", "success", nil)
}

type upstreamNotificationEvent struct {
	config UpstreamServerConfig
	method string
	params json.RawMessage
}

type upstreamReloadResult struct {
	RegistryVersion uint64
	Added           []string
	Removed         []string
	Kept            []string
}

type upstreamSupervisor struct {
	logger  *runtimeLogger
	clock   func() time.Time
	emitter *telemetry.Emitter

	mu              sync.RWMutex
	sessions        map[string]*upstreamSession
	serversByName   map[string]UpstreamServerConfig
	toolsByName     map[string]upstreamTool
	tools           []upstreamTool
	registryVersion uint64
	closed          bool
	refreshHook     func(server string)

	notifyCh   chan upstreamNotificationEvent
	notifyDone chan struct{}
	closeCh    chan struct{}
}

func newUpstreamSupervisor(configs []UpstreamServerConfig, logger *runtimeLogger, emitter *telemetry.Emitter, id identity.VerifiedIdentity, credentialBroker UpstreamCredentialBroker, recorder audit.Recorder) (*upstreamSupervisor, error) {
	sup := &upstreamSupervisor{
		logger:          logger,
		clock:           time.Now,
		emitter:         emitter,
		sessions:        map[string]*upstreamSession{},
		serversByName:   map[string]UpstreamServerConfig{},
		toolsByName:     map[string]upstreamTool{},
		tools:           []upstreamTool{},
		registryVersion: 1,
		notifyCh:        make(chan upstreamNotificationEvent, upstreamNotifyBufferSize),
		notifyDone:      make(chan struct{}),
		closeCh:         make(chan struct{}),
	}
	go sup.notificationLoop()
	if len(configs) == 0 {
		return sup, nil
	}
	configs, err := normalizeUpstreamRegistryConfigs(configs)
	if err != nil {
		sup.close()
		return nil, err
	}
	for _, config := range configs {
		session := newUpstreamSession(config, logger, sup.handleNotification, sup.clock, sup.emitter, id, credentialBroker, recorder)
		sup.serversByName[config.Name] = config
		sup.sessions[config.Name] = session
	}
	for _, config := range configs {
		tools, err := sup.enumerateTools(context.Background(), config.Name)
		if err != nil {
			sup.close()
			return nil, fmt.Errorf("load upstream mcp server %q: %w", config.Name, err)
		}
		for _, tool := range tools {
			if _, exists := sup.toolsByName[tool.DownstreamName]; exists {
				sup.close()
				return nil, fmt.Errorf("duplicate forwarded tool name %q", tool.DownstreamName)
			}
			sup.toolsByName[tool.DownstreamName] = tool
			sup.tools = append(sup.tools, tool)
		}
	}
	return sup, nil
}

func normalizeUpstreamRegistryConfigs(configs []UpstreamServerConfig) ([]UpstreamServerConfig, error) {
	normalized := make([]UpstreamServerConfig, 0, len(configs))
	seen := make(map[string]struct{}, len(configs))
	for _, config := range configs {
		name := strings.TrimSpace(config.Name)
		if name == "" {
			return nil, errors.New("upstream mcp server name is required")
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate upstream mcp server name %q", name)
		}
		config.Name = name
		seen[name] = struct{}{}
		normalized = append(normalized, config)
	}
	return normalized, nil
}

func (s *upstreamSupervisor) handleNotification(config UpstreamServerConfig, method string, params json.RawMessage) {
	select {
	case <-s.closeCh:
		return
	default:
	}
	event := upstreamNotificationEvent{config: config, method: method, params: params}
	select {
	case s.notifyCh <- event:
	case <-s.closeCh:
	default:
		if s.logger != nil {
			s.logger.Debug(fmt.Sprintf("upstream notification dropped (queue full) server=%q method=%q", config.Name, method))
		}
	}
}

func (s *upstreamSupervisor) notificationLoop() {
	defer close(s.notifyDone)
	for {
		select {
		case event := <-s.notifyCh:
			s.processNotification(event)
		case <-s.closeCh:
			for {
				select {
				case event := <-s.notifyCh:
					s.processNotification(event)
				default:
					return
				}
			}
		}
	}
}

func (s *upstreamSupervisor) processNotification(event upstreamNotificationEvent) {
	switch event.method {
	case "notifications/tools/list_changed":
		s.refreshServerTools(event.config.Name)
	case "notifications/initialized":
		// lifecycle notification; no action required
	default:
		if s.logger != nil {
			s.logger.Debug(fmt.Sprintf("upstream notification dropped server=%q method=%q", event.config.Name, event.method))
		}
	}
}

func (s *upstreamSupervisor) refreshServerTools(serverName string) {
	tools, err := s.enumerateTools(context.Background(), serverName)
	if err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("upstream tools refresh failed server=%q: %v", serverName, err))
		}
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	filtered := make([]upstreamTool, 0, len(s.tools))
	for _, tool := range s.tools {
		if tool.ServerName == serverName {
			delete(s.toolsByName, tool.DownstreamName)
			continue
		}
		filtered = append(filtered, tool)
	}
	skipped := make([]string, 0)
	for _, tool := range tools {
		if _, exists := s.toolsByName[tool.DownstreamName]; exists {
			skipped = append(skipped, tool.DownstreamName)
			continue
		}
		s.toolsByName[tool.DownstreamName] = tool
		filtered = append(filtered, tool)
	}
	s.tools = filtered
	hook := s.refreshHook
	s.mu.Unlock()
	if len(skipped) > 0 && s.logger != nil {
		s.logger.Debug(fmt.Sprintf("upstream tool refresh skipped duplicates server=%q count=%d", serverName, len(skipped)))
	}
	if hook != nil {
		hook(serverName)
	}
}

func (s *upstreamSupervisor) enumerateTools(ctx context.Context, serverName string) ([]upstreamTool, error) {
	s.mu.RLock()
	session, ok := s.sessions[serverName]
	config, configOK := s.serversByName[serverName]
	s.mu.RUnlock()
	if !ok || !configOK {
		return nil, fmt.Errorf("upstream mcp session missing for %q", serverName)
	}
	return enumerateToolsForSession(ctx, config, session)
}

func enumerateToolsForSession(ctx context.Context, config UpstreamServerConfig, session *upstreamSession) ([]upstreamTool, error) {
	if session == nil {
		return nil, fmt.Errorf("upstream mcp session missing for %q", config.Name)
	}
	result, err := session.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	return parseUpstreamTools(config, result)
}

func (s *upstreamSupervisor) registryVersionSnapshot() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registryVersion
}

func (s *upstreamSupervisor) reload(ctx context.Context, configs []UpstreamServerConfig, id identity.VerifiedIdentity, credentialBroker UpstreamCredentialBroker, recorder audit.Recorder) (upstreamReloadResult, error) {
	if s == nil {
		return upstreamReloadResult{}, errors.New("upstream supervisor not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	configs, err := normalizeUpstreamRegistryConfigs(configs)
	if err != nil {
		return upstreamReloadResult{}, err
	}
	configsByName := make(map[string]UpstreamServerConfig, len(configs))
	for _, config := range configs {
		configsByName[config.Name] = config
	}

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return upstreamReloadResult{}, errUpstreamClosed
	}
	existingSessions := make(map[string]*upstreamSession, len(s.sessions))
	for name, session := range s.sessions {
		existingSessions[name] = session
	}
	existingConfigs := make(map[string]UpstreamServerConfig, len(s.serversByName))
	for name, config := range s.serversByName {
		existingConfigs[name] = config
	}
	existingToolsByServer := make(map[string][]upstreamTool, len(s.serversByName))
	for _, tool := range s.tools {
		existingToolsByServer[tool.ServerName] = append(existingToolsByServer[tool.ServerName], tool)
	}
	currentVersion := s.registryVersion
	s.mu.RUnlock()

	result := upstreamReloadResult{RegistryVersion: currentVersion}
	replaced := make(map[string]bool)
	newConfigs := make([]UpstreamServerConfig, 0)
	for _, config := range configs {
		existing, ok := existingConfigs[config.Name]
		switch {
		case !ok:
			result.Added = append(result.Added, config.Name)
			newConfigs = append(newConfigs, config)
		case reflect.DeepEqual(existing, config):
			result.Kept = append(result.Kept, config.Name)
		default:
			replaced[config.Name] = true
			result.Added = append(result.Added, config.Name)
			result.Removed = append(result.Removed, config.Name)
			newConfigs = append(newConfigs, config)
		}
	}
	for name := range existingConfigs {
		if _, ok := configsByName[name]; !ok {
			result.Removed = append(result.Removed, name)
		}
	}

	newSessions := make(map[string]*upstreamSession, len(newConfigs))
	newToolsByServer := make(map[string][]upstreamTool, len(newConfigs))
	closeNewSessions := func() {
		for _, session := range newSessions {
			session.close()
		}
	}
	for _, config := range newConfigs {
		session := newUpstreamSession(config, s.logger, s.handleNotification, s.clock, s.emitter, id, credentialBroker, recorder)
		newSessions[config.Name] = session
		tools, err := enumerateToolsForSession(ctx, config, session)
		if err != nil {
			closeNewSessions()
			return result, fmt.Errorf("load upstream mcp server %q: %w", config.Name, err)
		}
		newToolsByServer[config.Name] = tools
	}

	finalSessions := make(map[string]*upstreamSession, len(configs))
	finalConfigs := make(map[string]UpstreamServerConfig, len(configs))
	finalToolsByName := make(map[string]upstreamTool)
	finalTools := make([]upstreamTool, 0)
	for _, config := range configs {
		session := newSessions[config.Name]
		tools := newToolsByServer[config.Name]
		if session == nil {
			session = existingSessions[config.Name]
			tools = existingToolsByServer[config.Name]
		}
		if session == nil {
			closeNewSessions()
			return result, fmt.Errorf("upstream mcp session missing for %q", config.Name)
		}
		finalSessions[config.Name] = session
		finalConfigs[config.Name] = config
		for _, tool := range tools {
			if _, exists := finalToolsByName[tool.DownstreamName]; exists {
				closeNewSessions()
				return result, fmt.Errorf("duplicate forwarded tool name %q", tool.DownstreamName)
			}
			finalToolsByName[tool.DownstreamName] = tool
			finalTools = append(finalTools, tool)
		}
	}

	removedSessions := make([]*upstreamSession, 0)
	for name, session := range existingSessions {
		if _, ok := configsByName[name]; !ok || replaced[name] {
			removedSessions = append(removedSessions, session)
		}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closeNewSessions()
		return result, errUpstreamClosed
	}
	s.sessions = finalSessions
	s.serversByName = finalConfigs
	s.toolsByName = finalToolsByName
	s.tools = finalTools
	s.registryVersion++
	result.RegistryVersion = s.registryVersion
	s.mu.Unlock()

	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	sort.Strings(result.Kept)
	for _, session := range removedSessions {
		drainRemovedUpstreamSession(session)
	}
	return result, nil
}

func drainRemovedUpstreamSession(session *upstreamSession) {
	if session == nil {
		return
	}
	go func() {
		session.callMu.Lock()
		defer session.callMu.Unlock()
		session.close()
	}()
}

func parseUpstreamTools(config UpstreamServerConfig, result any) ([]upstreamTool, error) {
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream tools/list result")
	}
	rawTools, ok := payload["tools"].([]any)
	if !ok {
		return nil, errors.New("upstream tools/list missing tools")
	}
	tools := make([]upstreamTool, 0, len(rawTools))
	for _, item := range rawTools {
		raw, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid upstream tool entry")
		}
		toolName, _ := raw["name"].(string)
		toolName = strings.TrimSpace(toolName)
		if toolName == "" {
			return nil, errors.New("upstream tool missing name")
		}
		description, _ := raw["description"].(string)
		schema, _ := raw["inputSchema"].(map[string]any)
		tools = append(tools, upstreamTool{
			ServerName:              config.Name,
			ToolName:                toolName,
			DownstreamName:          downstreamToolName(config.Name, toolName),
			Description:             description,
			InputSchema:             cloneMap(schema),
			AllowMissingInputSchema: config.AllowMissingToolSchemas,
		})
	}
	return tools, nil
}

func (s *upstreamSupervisor) callTool(ctx context.Context, serverName, toolName string, rawArgs json.RawMessage) (upstreamToolCallResult, error) {
	return s.callToolWithRequests(ctx, serverName, toolName, rawArgs, nil)
}

func (s *upstreamSupervisor) callToolWithRequests(ctx context.Context, serverName, toolName string, rawArgs json.RawMessage, handler upstreamRequestHandler) (upstreamToolCallResult, error) {
	s.mu.RLock()
	session, ok := s.sessions[serverName]
	s.mu.RUnlock()
	if !ok {
		return upstreamToolCallResult{}, fmt.Errorf("upstream mcp server %q not configured", serverName)
	}
	arguments := map[string]any{}
	if len(bytes.TrimSpace(rawArgs)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rawArgs))
		dec.UseNumber()
		if err := dec.Decode(&arguments); err != nil {
			return upstreamToolCallResult{}, fmt.Errorf("invalid forwarded tool arguments: %w", err)
		}
	}
	result, err := session.callWithRequests(ctx, "tools/call", map[string]any{
		"name":      toolName,
		"arguments": arguments,
	}, handler)
	if err != nil {
		return upstreamToolCallResult{}, err
	}
	return parseUpstreamCallResult(result)
}

func (s *upstreamSupervisor) envMetadata(serverName string) map[string]any {
	s.mu.RLock()
	session, ok := s.sessions[serverName]
	s.mu.RUnlock()
	if !ok || session == nil {
		return nil
	}
	hash := session.envShapeHash()
	if strings.TrimSpace(hash) == "" {
		return nil
	}
	return map[string]any{
		"upstream_env_shape_hash": hash,
	}
}

func (s *upstreamSupervisor) listResources(ctx context.Context) ([]map[string]any, error) {
	s.mu.RLock()
	servers := make([]string, 0, len(s.sessions))
	for name := range s.sessions {
		servers = append(servers, name)
	}
	s.mu.RUnlock()
	out := make([]map[string]any, 0)
	for _, serverName := range servers {
		items, err := s.listResourcesForServer(ctx, serverName)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

func (s *upstreamSupervisor) listResourcesForServer(ctx context.Context, serverName string) ([]map[string]any, error) {
	result, err := s.call(ctx, serverName, "resources/list", map[string]any{})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "method not found") {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream resources/list result")
	}
	rawItems, _ := payload["resources"].([]any)
	out := make([]map[string]any, 0, len(rawItems))
	for _, item := range rawItems {
		raw, ok := item.(map[string]any)
		if !ok {
			continue
		}
		upstreamURI, _ := raw["uri"].(string)
		if strings.TrimSpace(upstreamURI) == "" {
			continue
		}
		entry := cloneMap(raw)
		entry["uri"] = downstreamResourceURI(serverName, upstreamURI)
		entry["_meta"] = map[string]any{
			"upstream_server": serverName,
			"upstream_uri":    upstreamURI,
		}
		out = append(out, entry)
	}
	return out, nil
}

func (s *upstreamSupervisor) readResource(ctx context.Context, serverName, uri string) (map[string]any, error) {
	return s.readResourceWithRequests(ctx, serverName, uri, nil)
}

func (s *upstreamSupervisor) readResourceWithRequests(ctx context.Context, serverName, uri string, handler upstreamRequestHandler) (map[string]any, error) {
	result, err := s.callWithRequests(ctx, serverName, "resources/read", map[string]any{"uri": uri}, handler)
	if err != nil {
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream resources/read result")
	}
	return cloneMap(payload), nil
}

func (s *upstreamSupervisor) listPrompts(ctx context.Context) ([]map[string]any, error) {
	s.mu.RLock()
	servers := make([]string, 0, len(s.sessions))
	for name := range s.sessions {
		servers = append(servers, name)
	}
	s.mu.RUnlock()
	out := make([]map[string]any, 0)
	for _, serverName := range servers {
		items, err := s.listPromptsForServer(ctx, serverName)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

func (s *upstreamSupervisor) listPromptsForServer(ctx context.Context, serverName string) ([]map[string]any, error) {
	result, err := s.call(ctx, serverName, "prompts/list", map[string]any{})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "method not found") {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream prompts/list result")
	}
	rawItems, _ := payload["prompts"].([]any)
	out := make([]map[string]any, 0, len(rawItems))
	for _, item := range rawItems {
		raw, ok := item.(map[string]any)
		if !ok {
			continue
		}
		upstreamName, _ := raw["name"].(string)
		if strings.TrimSpace(upstreamName) == "" {
			continue
		}
		entry := cloneMap(raw)
		entry["name"] = downstreamPromptName(serverName, upstreamName)
		entry["_meta"] = map[string]any{
			"upstream_server": serverName,
			"upstream_prompt": upstreamName,
		}
		out = append(out, entry)
	}
	return out, nil
}

func (s *upstreamSupervisor) getPrompt(ctx context.Context, serverName, name string, arguments map[string]any) (map[string]any, error) {
	return s.getPromptWithRequests(ctx, serverName, name, arguments, nil)
}

func (s *upstreamSupervisor) getPromptWithRequests(ctx context.Context, serverName, name string, arguments map[string]any, handler upstreamRequestHandler) (map[string]any, error) {
	result, err := s.callWithRequests(ctx, serverName, "prompts/get", map[string]any{
		"name":      name,
		"arguments": arguments,
	}, handler)
	if err != nil {
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream prompts/get result")
	}
	return cloneMap(payload), nil
}

func (s *upstreamSupervisor) complete(ctx context.Context, serverName string, ref map[string]any, argument map[string]any, context map[string]any) (map[string]any, error) {
	return s.completeWithRequests(ctx, serverName, ref, argument, context, nil)
}

func (s *upstreamSupervisor) completeWithRequests(ctx context.Context, serverName string, ref map[string]any, argument map[string]any, context map[string]any, handler upstreamRequestHandler) (map[string]any, error) {
	params := map[string]any{
		"ref":      ref,
		"argument": argument,
	}
	if len(context) > 0 {
		params["context"] = context
	}
	result, err := s.callWithRequests(ctx, serverName, "completion/complete", params, handler)
	if err != nil {
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream completion/complete result")
	}
	return cloneMap(payload), nil
}

func (s *upstreamSupervisor) call(ctx context.Context, serverName, method string, params map[string]any) (any, error) {
	return s.callWithRequests(ctx, serverName, method, params, nil)
}

func (s *upstreamSupervisor) callWithRequests(ctx context.Context, serverName, method string, params map[string]any, handler upstreamRequestHandler) (any, error) {
	s.mu.RLock()
	session, ok := s.sessions[serverName]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("upstream mcp server %q not configured", serverName)
	}
	return session.callWithRequests(ctx, method, params, handler)
}

func (s *upstreamSupervisor) serverConfig(serverName string) (UpstreamServerConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	config, ok := s.serversByName[serverName]
	return config, ok
}

func (s *upstreamSupervisor) serverNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.sessions))
	for name := range s.sessions {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (s *upstreamSupervisor) snapshotTools() []upstreamTool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]upstreamTool, len(s.tools))
	copy(out, s.tools)
	return out
}

func (s *upstreamSupervisor) toolByName(name string) (upstreamTool, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tool, ok := s.toolsByName[name]
	return tool, ok
}

func (s *upstreamSupervisor) hasTools() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tools) > 0
}

func (s *upstreamSupervisor) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	sessions := make([]*upstreamSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mu.Unlock()
	select {
	case <-s.closeCh:
	default:
		close(s.closeCh)
	}
	for _, session := range sessions {
		session.close()
	}
	<-s.notifyDone
}

func (s *upstreamSupervisor) setBackoffForTest(initial, max time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.sessions {
		session.setBackoffForTest(initial, max)
	}
}

func (s *upstreamSupervisor) setRefreshHookForTest(hook func(server string)) {
	s.mu.Lock()
	s.refreshHook = hook
	s.mu.Unlock()
}

func (s *upstreamSupervisor) breakerStates() []upstreamBreakerSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]upstreamBreakerSnapshot, 0, len(s.sessions))
	for name, session := range s.sessions {
		snapshot := session.breakerSnapshot()
		if snapshot.Server == "" {
			snapshot.Server = name
		}
		out = append(out, snapshot)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Server < out[j].Server
	})
	return out
}

func (s *upstreamSupervisor) sessionForTest(name string) *upstreamSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[name]
}

func hasJSONID(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return false
	}
	return true
}

func rpcIDKey(id any) string {
	switch v := id.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	}
	data, err := json.Marshal(id)
	if err != nil {
		return ""
	}
	return string(data)
}
