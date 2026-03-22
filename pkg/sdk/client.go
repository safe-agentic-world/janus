package sdk

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

const (
	DefaultTimeout        = 5 * time.Second
	DefaultUserAgent      = "nomos-go-sdk/0.1"
	SupportedHTTPContract = "v1"
	defaultActionPrefix   = "sdk_act"
	defaultTracePrefix    = "sdk_trace"
)

type Logger interface {
	Printf(format string, args ...any)
}

type Config struct {
	BaseURL     string
	BearerToken string
	AgentID     string
	AgentSecret string
	Timeout     time.Duration
	HTTPClient  *http.Client
	UserAgent   string
	Logger      Logger
}

type Client struct {
	baseURL     string
	bearerToken string
	agentID     string
	agentSecret string
	httpClient  *http.Client
	userAgent   string
	logger      Logger
}

func NewClient(cfg Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("base_url is required")
	}
	if _, err := neturl.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("base_url: %w", err)
	}
	if strings.TrimSpace(cfg.BearerToken) == "" {
		return nil, errors.New("bearer_token is required")
	}
	if strings.TrimSpace(cfg.AgentID) == "" {
		return nil, errors.New("agent_id is required")
	}
	if strings.TrimSpace(cfg.AgentSecret) == "" {
		return nil, errors.New("agent_secret is required")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	}
	userAgent := strings.TrimSpace(cfg.UserAgent)
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	return &Client{
		baseURL:     baseURL,
		bearerToken: cfg.BearerToken,
		agentID:     cfg.AgentID,
		agentSecret: cfg.AgentSecret,
		httpClient:  httpClient,
		userAgent:   userAgent,
		logger:      cfg.Logger,
	}, nil
}

func SignRequestBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func GenerateID(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "sdk"
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return prefix + "_fallback"
	}
	return prefix + "_" + hex.EncodeToString(buf)
}

func (c *Client) RunAction(ctx context.Context, req ActionRequest) (DecisionResponse, error) {
	req.ensureDefaults()
	if err := req.Validate(); err != nil {
		return DecisionResponse{}, err
	}
	return doJSON[DecisionResponse](ctx, c, http.MethodPost, "/action", req)
}

func (c *Client) ExplainAction(ctx context.Context, req ActionRequest) (ExplainResponse, error) {
	req.ensureDefaults()
	if err := req.Validate(); err != nil {
		return ExplainResponse{}, err
	}
	return doJSON[ExplainResponse](ctx, c, http.MethodPost, "/explain", req)
}

func (c *Client) DecideApproval(ctx context.Context, req ApprovalDecisionRequest) (DecisionResponse, error) {
	req.ApprovalID = strings.TrimSpace(req.ApprovalID)
	req.Decision = strings.TrimSpace(req.Decision)
	if req.ApprovalID == "" || req.Decision == "" {
		return DecisionResponse{}, errors.New("approval_id and decision are required")
	}
	return doJSON[DecisionResponse](ctx, c, http.MethodPost, "/approvals/decide", req)
}

func doJSON[T any](ctx context.Context, c *Client, method, endpoint string, requestBody any) (T, error) {
	var zero T
	data, err := json.Marshal(requestBody)
	if err != nil {
		return zero, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+endpoint, bytes.NewReader(data))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	req.Header.Set("X-Nomos-Agent-Id", c.agentID)
	req.Header.Set("X-Nomos-Agent-Signature", SignRequestBody(c.agentSecret, data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("X-Nomos-SDK-Contract", SupportedHTTPContract)

	started := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.debugf("%s %s transport_error duration_ms=%d", method, endpoint, time.Since(started).Milliseconds())
		return zero, classifyTransportError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return zero, err
	}
	c.debugf("%s %s status=%d duration_ms=%d", method, endpoint, resp.StatusCode, time.Since(started).Milliseconds())
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, decodeGatewayError(resp.StatusCode, body)
	}
	var decoded T
	if err := json.Unmarshal(body, &decoded); err != nil {
		return zero, &Error{Kind: ErrorKindDecode, Message: err.Error(), Retryable: false}
	}
	return decoded, nil
}

func (c *Client) debugf(format string, args ...any) {
	if c == nil || c.logger == nil {
		return
	}
	c.logger.Printf(format, args...)
}

func classifyTransportError(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &Error{Kind: ErrorKindTimeout, Message: err.Error(), Retryable: true}
	}
	return &Error{Kind: ErrorKindTransport, Message: err.Error(), Retryable: true}
}
