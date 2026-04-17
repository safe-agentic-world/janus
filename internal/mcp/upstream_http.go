package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	upstreamHTTPRequestTimeout = 30 * time.Second
	upstreamHTTPHandshakeID    = "initialize"
	upstreamHTTPUserAgent      = "nomos-upstream-gateway/v1"
	upstreamSSEReadCap         = 4 * 1024 * 1024
)

type upstreamHTTPConn struct {
	config       UpstreamServerConfig
	endpoint     *neturl.URL
	allowedHosts map[string]struct{}
	httpClient   *http.Client
	legacySSE    bool
	notifyFn     func(method string, params json.RawMessage)
	authHeaders  map[string]string

	sessionID atomic.Value // string
	postURL   atomic.Value // *neturl.URL

	mu      sync.Mutex
	pending map[string]chan rpcMessage
	nextID  int64
	closed  bool
	err     error

	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	doneOnce   sync.Once
	streamDone chan struct{}
}

func startUpstreamHTTPConn(config UpstreamServerConfig, notify func(method string, params json.RawMessage), legacySSE bool) (*upstreamHTTPConn, error) {
	raw := strings.TrimSpace(config.Endpoint)
	if raw == "" {
		return nil, errors.New("upstream endpoint is required")
	}
	endpoint, err := neturl.Parse(raw)
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid upstream endpoint %q", raw)
	}
	switch endpoint.Scheme {
	case "https":
	case "http":
		if !config.TLSInsecure {
			return nil, errors.New("upstream endpoint must use https unless tls_insecure is set")
		}
	default:
		return nil, fmt.Errorf("unsupported upstream endpoint scheme %q", endpoint.Scheme)
	}

	allowed := map[string]struct{}{}
	for _, host := range config.AllowedHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" {
			allowed[host] = struct{}{}
		}
	}
	if len(allowed) > 0 {
		if _, ok := allowed[strings.ToLower(endpoint.Hostname())]; !ok {
			return nil, fmt.Errorf("upstream endpoint host %q not in allowed_hosts", endpoint.Hostname())
		}
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.TLSInsecure {
		tlsCfg.InsecureSkipVerify = true
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		DisableCompression:    true,
		ResponseHeaderTimeout: upstreamHTTPRequestTimeout,
	}
	client := &http.Client{Transport: transport}

	authHeaders := map[string]string{}
	switch strings.TrimSpace(config.AuthType) {
	case "bearer":
		token := strings.TrimSpace(config.AuthToken)
		if token == "" {
			return nil, errors.New("upstream bearer auth token missing")
		}
		authHeaders["Authorization"] = "Bearer " + token
	case "header":
		if header := strings.TrimSpace(config.AuthHeader); header != "" {
			authHeaders[header] = config.AuthValue
		}
		for k, v := range config.AuthHeaders {
			k = strings.TrimSpace(k)
			if k != "" {
				authHeaders[k] = v
			}
		}
		if len(authHeaders) == 0 {
			return nil, errors.New("upstream header auth requires at least one header")
		}
	case "":
		// no auth
	default:
		return nil, fmt.Errorf("unsupported upstream auth type %q", config.AuthType)
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn := &upstreamHTTPConn{
		config:       config,
		endpoint:     endpoint,
		allowedHosts: allowed,
		httpClient:   client,
		legacySSE:    legacySSE,
		notifyFn:     notify,
		authHeaders:  authHeaders,
		pending:      map[string]chan rpcMessage{},
		ctx:          ctx,
		cancel:       cancel,
		done:         make(chan struct{}),
		streamDone:   make(chan struct{}),
	}
	conn.postURL.Store(endpoint)

	if legacySSE {
		if err := conn.startLegacySSE(); err != nil {
			conn.shutdown(err)
			return nil, upstreamStageError(config, "sse_connect", err, "")
		}
	} else {
		close(conn.streamDone)
	}

	if err := conn.handshake(); err != nil {
		conn.shutdown(err)
		return nil, upstreamStageError(config, "initialize", err, "")
	}
	return conn, nil
}

func (c *upstreamHTTPConn) doneCh() <-chan struct{} { return c.done }

func (c *upstreamHTTPConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *upstreamHTTPConn) shutdown(err error) {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		if c.err == nil {
			c.err = err
		}
	}
	pending := c.pending
	c.pending = map[string]chan rpcMessage{}
	c.mu.Unlock()
	for _, ch := range pending {
		select {
		case ch <- rpcMessage{err: errUpstreamUnavailable}:
		default:
		}
	}
	c.doneOnce.Do(func() { close(c.done) })
	if c.cancel != nil {
		c.cancel()
	}
	if tr, ok := c.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func (c *upstreamHTTPConn) close() {
	c.shutdown(errUpstreamClosed)
	<-c.streamDone
}

func (c *upstreamHTTPConn) allocateRequestID() string {
	id := atomic.AddInt64(&c.nextID, 1)
	return "req-" + strconv.FormatInt(id, 10)
}

func (c *upstreamHTTPConn) handshake() error {
	resp, err := c.sendRequestRaw(upstreamHTTPHandshakeID, "initialize", map[string]any{
		"protocolVersion": SupportedProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "nomos-upstream-gateway",
			"version": "v1",
		},
	})
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("upstream initialize returned empty response")
	}
	if resp.Error != nil {
		return errors.New(resp.Error.Message)
	}
	if err := c.sendNotificationRaw("notifications/initialized", map[string]any{}); err != nil {
		return err
	}
	return nil
}

func (c *upstreamHTTPConn) callMethod(method string, params map[string]any) (any, error) {
	if c.isClosed() {
		return nil, errUpstreamUnavailable
	}
	id := c.allocateRequestID()
	resp, err := c.sendRequestRaw(id, method, params)
	if err != nil {
		c.shutdown(err)
		return nil, errUpstreamUnavailable
	}
	if resp == nil {
		return nil, errUpstreamUnavailable
	}
	if resp.Error != nil {
		return nil, errors.New(resp.Error.Message)
	}
	return resp.Result, nil
}

func (c *upstreamHTTPConn) sendRequestRaw(id, method string, params map[string]any) (*rpcResponse, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if c.legacySSE {
		return c.postLegacySSERequest(id, body)
	}
	return c.postStreamableHTTPRequest(id, body)
}

func (c *upstreamHTTPConn) sendNotificationRaw(method string, params map[string]any) error {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if c.legacySSE {
		_, err := c.doPOST(body, true)
		return err
	}
	_, err = c.doPOST(body, true)
	return err
}

func (c *upstreamHTTPConn) checkAllowlist(host string) error {
	if len(c.allowedHosts) == 0 {
		return nil
	}
	if _, ok := c.allowedHosts[strings.ToLower(host)]; ok {
		return nil
	}
	return fmt.Errorf("upstream host %q not in allowed_hosts", host)
}

func (c *upstreamHTTPConn) doPOST(body []byte, notification bool) (*http.Response, error) {
	postURL, _ := c.postURL.Load().(*neturl.URL)
	if postURL == nil {
		return nil, errors.New("upstream post url not set")
	}
	if err := c.checkAllowlist(postURL.Hostname()); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, postURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if notification {
		req.Header.Set("Accept", "application/json, text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	req.Header.Set("User-Agent", upstreamHTTPUserAgent)
	for k, v := range c.authHeaders {
		req.Header.Set(k, v)
	}
	if sid, _ := c.sessionID.Load().(string); sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID.Store(sid)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, fmt.Errorf("upstream auth failed: %s", resp.Status)
	}
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		resp.Body.Close()
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("upstream http %s: %s", resp.Status, bytes.TrimSpace(snippet))
	}
	return resp, nil
}

func (c *upstreamHTTPConn) postStreamableHTTPRequest(id string, body []byte) (*rpcResponse, error) {
	resp, err := c.doPOST(body, false)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "text/event-stream") {
		return c.readResponseFromSSE(resp.Body, id)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, upstreamSSEReadCap))
	if err != nil {
		return nil, err
	}
	return decodeRPCResponse(bytes.TrimSpace(data))
}

func (c *upstreamHTTPConn) postLegacySSERequest(id string, body []byte) (*rpcResponse, error) {
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

	if _, err := c.doPOST(body, false); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}
	select {
	case msg := <-ch:
		if msg.err != nil {
			return nil, msg.err
		}
		return msg.resp, nil
	case <-c.done:
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, errUpstreamUnavailable
	}
}

func (c *upstreamHTTPConn) readResponseFromSSE(body io.Reader, wantID string) (*rpcResponse, error) {
	reader := bufio.NewReader(body)
	for {
		evt, err := readSSEEvent(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("upstream sse stream closed without response")
			}
			return nil, err
		}
		if evt.data == "" {
			continue
		}
		resp, matched, err := c.processSSEMessage([]byte(evt.data), wantID)
		if err != nil {
			return nil, err
		}
		if matched {
			return resp, nil
		}
	}
}

func (c *upstreamHTTPConn) processSSEMessage(raw []byte, wantID string) (*rpcResponse, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false, nil
	}
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, false, fmt.Errorf("invalid upstream sse payload: %w", err)
	}
	if envelope.Method != "" && !hasJSONID(envelope.ID) {
		if c.notifyFn != nil {
			var note struct {
				Params json.RawMessage `json:"params"`
			}
			if err := json.Unmarshal(trimmed, &note); err == nil {
				c.notifyFn(envelope.Method, note.Params)
			} else {
				c.notifyFn(envelope.Method, nil)
			}
		}
		return nil, false, nil
	}
	resp, err := decodeRPCResponse(trimmed)
	if err != nil {
		return nil, false, err
	}
	if resp == nil {
		return nil, false, nil
	}
	idKey := rpcIDKey(resp.ID)
	if wantID != "" && idKey == wantID {
		return resp, true, nil
	}
	if c.legacySSE {
		c.mu.Lock()
		ch, ok := c.pending[idKey]
		if ok {
			delete(c.pending, idKey)
		}
		c.mu.Unlock()
		if ok {
			ch <- rpcMessage{resp: resp}
		}
	}
	return nil, false, nil
}

func decodeRPCResponse(body []byte) (*rpcResponse, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("empty rpc response")
	}
	var resp rpcResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("invalid rpc response: %w", err)
	}
	return &resp, nil
}

type sseEvent struct {
	event string
	data  string
}

func readSSEEvent(reader *bufio.Reader) (sseEvent, error) {
	var evt sseEvent
	var dataBuf strings.Builder
	sawLine := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if !sawLine && line == "" {
					return evt, io.EOF
				}
				if dataBuf.Len() > 0 {
					evt.data = dataBuf.String()
				}
				if evt.data == "" && evt.event == "" {
					return evt, io.EOF
				}
				return evt, nil
			}
			return evt, err
		}
		sawLine = true
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if dataBuf.Len() > 0 {
				evt.data = dataBuf.String()
			}
			return evt, nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field := line
		value := ""
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			field = line[:idx]
			value = line[idx+1:]
			if strings.HasPrefix(value, " ") {
				value = value[1:]
			}
		}
		switch field {
		case "event":
			evt.event = value
		case "data":
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(value)
		}
	}
}

func (c *upstreamHTTPConn) startLegacySSE() error {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.endpoint.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", upstreamHTTPUserAgent)
	for k, v := range c.authHeaders {
		req.Header.Set(k, v)
	}
	if err := c.checkAllowlist(c.endpoint.Hostname()); err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return fmt.Errorf("legacy sse GET failed: %s", resp.Status)
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "text/event-stream") {
		resp.Body.Close()
		return fmt.Errorf("legacy sse unexpected content-type %q", ct)
	}
	reader := bufio.NewReader(resp.Body)
	endpointDeadline := time.Now().Add(upstreamHTTPRequestTimeout)
	for {
		if time.Now().After(endpointDeadline) {
			resp.Body.Close()
			return errors.New("legacy sse endpoint event not received")
		}
		evt, err := readSSEEvent(reader)
		if err != nil {
			resp.Body.Close()
			return err
		}
		if evt.event == "endpoint" {
			postURL, perr := c.endpoint.Parse(strings.TrimSpace(evt.data))
			if perr != nil || postURL.Host == "" {
				resp.Body.Close()
				return fmt.Errorf("invalid legacy sse endpoint event %q", evt.data)
			}
			if err := c.checkAllowlist(postURL.Hostname()); err != nil {
				resp.Body.Close()
				return err
			}
			c.postURL.Store(postURL)
			break
		}
	}
	go c.legacySSEReadLoop(resp)
	return nil
}

func (c *upstreamHTTPConn) legacySSEReadLoop(resp *http.Response) {
	defer close(c.streamDone)
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	for {
		evt, err := readSSEEvent(reader)
		if err != nil {
			c.shutdown(err)
			return
		}
		if evt.data == "" {
			continue
		}
		if _, _, err := c.processSSEMessage([]byte(evt.data), ""); err != nil {
			c.shutdown(err)
			return
		}
	}
}
