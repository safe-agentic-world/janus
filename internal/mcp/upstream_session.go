package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errUpstreamClosed      = errors.New("upstream mcp session closed")
	errUpstreamUnavailable = errors.New("upstream mcp session unavailable")
)

type upstreamTransport interface {
	callMethod(method string, params map[string]any) (any, error)
	setRequestHandler(handler upstreamRequestHandler)
	isClosed() bool
	close()
	doneCh() <-chan struct{}
}

type upstreamRequestHandler func(req rpcRequest) *rpcResponse

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
	config   UpstreamServerConfig
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	writer   *bufio.Writer
	notifyFn func(method string, params json.RawMessage)

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
	cmd.Env = os.Environ()
	for key, value := range config.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
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
		config:     config,
		cmd:        cmd,
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		writer:     bufio.NewWriter(stdin),
		pending:    map[string]chan rpcMessage{},
		done:       make(chan struct{}),
		stderrDone: make(chan struct{}),
		notifyFn:   notify,
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
	if _, err := c.sendRequest("initialize", "initialize", map[string]any{
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

func (c *upstreamConn) sendRequest(id, method string, params map[string]any) (*rpcResponse, error) {
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
			return msg.resp, errors.New(msg.resp.Error.Message)
		}
		return msg.resp, nil
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

func (c *upstreamConn) callMethod(method string, params map[string]any) (any, error) {
	id := c.allocateRequestID()
	resp, err := c.sendRequest(id, method, params)
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

type upstreamSession struct {
	config         UpstreamServerConfig
	logger         *runtimeLogger
	onNotification func(config UpstreamServerConfig, method string, params json.RawMessage)

	mu             sync.Mutex
	callMu         sync.Mutex
	conn           upstreamTransport
	starting       bool
	closed         bool
	lastFailureAt  time.Time
	attempts       int
	backoffInitial time.Duration
	backoffMax     time.Duration
	clock          func() time.Time
}

func newUpstreamSession(config UpstreamServerConfig, logger *runtimeLogger, notifyFn func(UpstreamServerConfig, string, json.RawMessage), clock func() time.Time) *upstreamSession {
	if clock == nil {
		clock = time.Now
	}
	return &upstreamSession{
		config:         config,
		logger:         logger,
		onNotification: notifyFn,
		clock:          clock,
		backoffInitial: defaultUpstreamBackoffInitial,
		backoffMax:     defaultUpstreamBackoffMax,
	}
}

func (s *upstreamSession) connForTest() *upstreamConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if conn, ok := s.conn.(*upstreamConn); ok {
		return conn
	}
	return nil
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

func (s *upstreamSession) ensureConn() (upstreamTransport, error) {
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
	s.starting = true
	s.mu.Unlock()

	conn, startErr := startUpstreamTransport(s.config, func(method string, params json.RawMessage) {
		if s.onNotification != nil {
			s.onNotification(s.config, method, params)
		}
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	s.starting = false
	if s.closed {
		if conn != nil {
			go conn.close()
		}
		return nil, errUpstreamClosed
	}
	if startErr != nil {
		s.attempts++
		s.lastFailureAt = s.clock()
		return nil, startErr
	}
	s.conn = conn
	s.attempts = 0
	s.lastFailureAt = time.Time{}
	return conn, nil
}

func (s *upstreamSession) call(method string, params map[string]any) (any, error) {
	return s.callWithRequests(method, params, nil)
}

func (s *upstreamSession) callWithRequests(method string, params map[string]any, handler upstreamRequestHandler) (any, error) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	conn, err := s.ensureConn()
	if err != nil {
		return nil, err
	}
	conn.setRequestHandler(handler)
	defer conn.setRequestHandler(nil)
	result, callErr := conn.callMethod(method, params)
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
}

type upstreamNotificationEvent struct {
	config UpstreamServerConfig
	method string
	params json.RawMessage
}

type upstreamSupervisor struct {
	logger *runtimeLogger
	clock  func() time.Time

	mu            sync.RWMutex
	sessions      map[string]*upstreamSession
	serversByName map[string]UpstreamServerConfig
	toolsByName   map[string]upstreamTool
	tools         []upstreamTool
	closed        bool
	refreshHook   func(server string)

	notifyCh   chan upstreamNotificationEvent
	notifyDone chan struct{}
	closeCh    chan struct{}
}

func newUpstreamSupervisor(configs []UpstreamServerConfig, logger *runtimeLogger) (*upstreamSupervisor, error) {
	sup := &upstreamSupervisor{
		logger:        logger,
		clock:         time.Now,
		sessions:      map[string]*upstreamSession{},
		serversByName: map[string]UpstreamServerConfig{},
		toolsByName:   map[string]upstreamTool{},
		tools:         []upstreamTool{},
		notifyCh:      make(chan upstreamNotificationEvent, upstreamNotifyBufferSize),
		notifyDone:    make(chan struct{}),
		closeCh:       make(chan struct{}),
	}
	go sup.notificationLoop()
	if len(configs) == 0 {
		return sup, nil
	}
	for _, config := range configs {
		if _, exists := sup.serversByName[config.Name]; exists {
			sup.close()
			return nil, fmt.Errorf("duplicate upstream mcp server name %q", config.Name)
		}
		session := newUpstreamSession(config, logger, sup.handleNotification, sup.clock)
		sup.serversByName[config.Name] = config
		sup.sessions[config.Name] = session
	}
	for _, config := range configs {
		tools, err := sup.enumerateTools(config.Name)
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
	tools, err := s.enumerateTools(serverName)
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

func (s *upstreamSupervisor) enumerateTools(serverName string) ([]upstreamTool, error) {
	s.mu.RLock()
	session, ok := s.sessions[serverName]
	config, configOK := s.serversByName[serverName]
	s.mu.RUnlock()
	if !ok || !configOK {
		return nil, fmt.Errorf("upstream mcp session missing for %q", serverName)
	}
	result, err := session.call("tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	return parseUpstreamTools(config, result)
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
			ServerName:     config.Name,
			ToolName:       toolName,
			DownstreamName: downstreamToolName(config.Name, toolName),
			Description:    description,
			InputSchema:    cloneMap(schema),
		})
	}
	return tools, nil
}

func (s *upstreamSupervisor) callTool(serverName, toolName string, rawArgs json.RawMessage) (string, error) {
	return s.callToolWithRequests(serverName, toolName, rawArgs, nil)
}

func (s *upstreamSupervisor) callToolWithRequests(serverName, toolName string, rawArgs json.RawMessage, handler upstreamRequestHandler) (string, error) {
	s.mu.RLock()
	session, ok := s.sessions[serverName]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("upstream mcp server %q not configured", serverName)
	}
	arguments := map[string]any{}
	if len(bytes.TrimSpace(rawArgs)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rawArgs))
		dec.UseNumber()
		if err := dec.Decode(&arguments); err != nil {
			return "", fmt.Errorf("invalid forwarded tool arguments: %w", err)
		}
	}
	result, err := session.callWithRequests("tools/call", map[string]any{
		"name":      toolName,
		"arguments": arguments,
	}, handler)
	if err != nil {
		return "", err
	}
	return stringifyUpstreamCallResult(result)
}

func (s *upstreamSupervisor) listResources() ([]map[string]any, error) {
	s.mu.RLock()
	servers := make([]string, 0, len(s.sessions))
	for name := range s.sessions {
		servers = append(servers, name)
	}
	s.mu.RUnlock()
	out := make([]map[string]any, 0)
	for _, serverName := range servers {
		items, err := s.listResourcesForServer(serverName)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

func (s *upstreamSupervisor) listResourcesForServer(serverName string) ([]map[string]any, error) {
	result, err := s.call(serverName, "resources/list", map[string]any{})
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

func (s *upstreamSupervisor) readResource(serverName, uri string) (map[string]any, error) {
	return s.readResourceWithRequests(serverName, uri, nil)
}

func (s *upstreamSupervisor) readResourceWithRequests(serverName, uri string, handler upstreamRequestHandler) (map[string]any, error) {
	result, err := s.callWithRequests(serverName, "resources/read", map[string]any{"uri": uri}, handler)
	if err != nil {
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream resources/read result")
	}
	return cloneMap(payload), nil
}

func (s *upstreamSupervisor) listPrompts() ([]map[string]any, error) {
	s.mu.RLock()
	servers := make([]string, 0, len(s.sessions))
	for name := range s.sessions {
		servers = append(servers, name)
	}
	s.mu.RUnlock()
	out := make([]map[string]any, 0)
	for _, serverName := range servers {
		items, err := s.listPromptsForServer(serverName)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

func (s *upstreamSupervisor) listPromptsForServer(serverName string) ([]map[string]any, error) {
	result, err := s.call(serverName, "prompts/list", map[string]any{})
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

func (s *upstreamSupervisor) getPrompt(serverName, name string, arguments map[string]any) (map[string]any, error) {
	return s.getPromptWithRequests(serverName, name, arguments, nil)
}

func (s *upstreamSupervisor) getPromptWithRequests(serverName, name string, arguments map[string]any, handler upstreamRequestHandler) (map[string]any, error) {
	result, err := s.callWithRequests(serverName, "prompts/get", map[string]any{
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

func (s *upstreamSupervisor) complete(serverName string, ref map[string]any, argument map[string]any, context map[string]any) (map[string]any, error) {
	return s.completeWithRequests(serverName, ref, argument, context, nil)
}

func (s *upstreamSupervisor) completeWithRequests(serverName string, ref map[string]any, argument map[string]any, context map[string]any, handler upstreamRequestHandler) (map[string]any, error) {
	params := map[string]any{
		"ref":      ref,
		"argument": argument,
	}
	if len(context) > 0 {
		params["context"] = context
	}
	result, err := s.callWithRequests(serverName, "completion/complete", params, handler)
	if err != nil {
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream completion/complete result")
	}
	return cloneMap(payload), nil
}

func (s *upstreamSupervisor) call(serverName, method string, params map[string]any) (any, error) {
	return s.callWithRequests(serverName, method, params, nil)
}

func (s *upstreamSupervisor) callWithRequests(serverName, method string, params map[string]any, handler upstreamRequestHandler) (any, error) {
	s.mu.RLock()
	session, ok := s.sessions[serverName]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("upstream mcp server %q not configured", serverName)
	}
	return session.callWithRequests(method, params, handler)
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
