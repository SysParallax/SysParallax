// Package browser fournit un navigateur headless minimal et isole pour les
// validations Active qui nécessitent un rendu réel.
package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

var (
	ErrBrowserUnavailable = errors.New("headless browser unavailable")
	ErrOriginBlocked      = errors.New("browser origin blocked")
	ErrNavigationLimit    = errors.New("browser navigation limit reached")
)

type Config struct {
	ExecutablePath string
	AllowedOrigins []string
	Timeout        time.Duration
	MaxPages       int
	MaxNavigations int
	MaxDOMBytes    int
}

type Event struct {
	Type   string    `json:"type"`
	URL    string    `json:"url,omitempty"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

type Result struct {
	FinalURL       string   `json:"final_url,omitempty"`
	FinalOrigin    string   `json:"final_origin,omitempty"`
	DOM            string   `json:"dom,omitempty"`
	Marker         string   `json:"marker,omitempty"`
	MarkerObserved bool     `json:"marker_observed"`
	Navigations    []string `json:"navigations,omitempty"`
	Events         []Event  `json:"events,omitempty"`
	BlockedURLs    []string `json:"blocked_urls,omitempty"`
}

type Runner struct {
	config Config
}

func New(config Config) *Runner {
	if config.Timeout <= 0 {
		config.Timeout = 12 * time.Second
	}
	if config.MaxPages <= 0 {
		config.MaxPages = 1
	}
	if config.MaxPages > 1 {
		config.MaxPages = 1
	}
	if config.MaxNavigations <= 0 {
		config.MaxNavigations = 5
	}
	if config.MaxDOMBytes <= 0 {
		config.MaxDOMBytes = 256 * 1024
	}
	config.AllowedOrigins = normalizeOrigins(config.AllowedOrigins)
	return &Runner{config: config}
}

func (r *Runner) Run(ctx context.Context, targetURL, marker string) (*Result, error) {
	if r == nil {
		return nil, ErrBrowserUnavailable
	}
	targetOrigin := originOf(targetURL)
	if targetOrigin == "" {
		return nil, fmt.Errorf("%w: target URL must be http(s)", ErrOriginBlocked)
	}
	allowed := r.config.AllowedOrigins
	if len(allowed) == 0 {
		allowed = []string{targetOrigin}
	}
	if !originAllowed(targetURL, allowed) {
		return nil, fmt.Errorf("%w: %s", ErrOriginBlocked, targetOrigin)
	}

	executable, err := discoverExecutable(r.config.ExecutablePath)
	if err != nil {
		return nil, err
	}
	profile, err := os.MkdirTemp("", "auditcore-browser-")
	if err != nil {
		return nil, fmt.Errorf("create browser profile: %w", err)
	}
	defer os.RemoveAll(profile)

	port, err := freePort()
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()
	args := []string{
		"--headless=new", "--disable-gpu", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--disable-default-apps", "--no-first-run",
		"--no-default-browser-check", "--incognito", "--user-data-dir=" + profile,
		"--remote-debugging-address=127.0.0.1", fmt.Sprintf("--remote-debugging-port=%d", port),
		"--remote-allow-origins=*", "about:blank",
	}
	cmd := exec.CommandContext(runCtx, executable, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start headless browser: %w", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	version, err := waitForVersion(runCtx, port)
	if err != nil {
		return nil, err
	}
	target, err := openTarget(runCtx, port)
	if err != nil {
		return nil, err
	}
	conn, err := websocket.Dial(target.WebSocketDebuggerURL, "", "http://127.0.0.1")
	if err != nil {
		return nil, fmt.Errorf("connect browser debugging protocol: %w", err)
	}
	defer conn.Close()

	state := &runState{result: &Result{Marker: marker}, allowed: allowed, maxNavigations: r.config.MaxNavigations, maxDOMBytes: r.config.MaxDOMBytes}
	client := &cdpClient{conn: conn, state: state}
	if _, err = client.call(runCtx, "Page.enable", map[string]any{}); err != nil {
		return nil, fmt.Errorf("Page.enable: %w", err)
	}
	if _, err = client.call(runCtx, "Runtime.enable", map[string]any{}); err != nil {
		return nil, fmt.Errorf("Runtime.enable: %w", err)
	}
	if _, err = client.call(runCtx, "Fetch.enable", map[string]any{"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}}}); err != nil {
		return nil, fmt.Errorf("Fetch.enable: %w", err)
	}
	if _, err = client.call(runCtx, "Page.navigate", map[string]any{"url": targetURL}); err != nil {
		return nil, fmt.Errorf("Page.navigate: %w", err)
	}
	if err := client.waitForLoad(runCtx, 3*time.Second); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if state.blockedError != nil {
		return nil, state.blockedError
	}

	value, err := client.evaluate(runCtx, "document.documentElement ? document.documentElement.outerHTML : ''")
	if err != nil {
		return nil, fmt.Errorf("evaluate DOM: %w", err)
	}
	state.result.DOM = redactText(truncate(value, state.maxDOMBytes))
	if marker != "" && (strings.Contains(state.result.DOM, marker) || state.markerObserved) {
		state.result.MarkerObserved = true
	}
	if state.result.FinalURL == "" {
		location, locationErr := client.evaluate(runCtx, "window.location.href")
		if locationErr == nil {
			state.result.FinalURL = location
			state.result.FinalOrigin = originOf(location)
		}
	}
	_ = version
	state.addEvent("browser_connected", "", "CDP connected")
	return state.result, nil
}

type runState struct {
	result         *Result
	allowed        []string
	maxNavigations int
	maxDOMBytes    int
	markerObserved bool
	blockedError   error
	mu             sync.Mutex
}

func (s *runState) addEvent(kind, rawURL, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result.Events = append(s.result.Events, Event{Type: kind, URL: redactURL(rawURL), Detail: detail, At: time.Now().UTC()})
}

func (s *runState) handle(method string, params json.RawMessage, client *cdpClient) {
	switch method {
	case "Fetch.requestPaused":
		var event struct {
			RequestID string `json:"requestId"`
			Request   struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		if json.Unmarshal(params, &event) != nil {
			return
		}
		if originAllowed(event.Request.URL, s.allowed) {
			_ = client.send("Fetch.continueRequest", map[string]any{"requestId": event.RequestID})
		} else {
			_ = client.send("Fetch.failRequest", map[string]any{"requestId": event.RequestID, "errorReason": "BlockedByClient"})
			s.result.BlockedURLs = append(s.result.BlockedURLs, redactURL(event.Request.URL))
			s.blockedError = fmt.Errorf("%w: %s", ErrOriginBlocked, originOf(event.Request.URL))
			s.addEvent("request_blocked", event.Request.URL, "origin outside allowlist")
		}
	case "Page.frameNavigated":
		var event struct {
			Frame struct {
				ParentID string `json:"parentId"`
				URL      string `json:"url"`
			} `json:"frame"`
		}
		if json.Unmarshal(params, &event) != nil || event.Frame.ParentID != "" {
			return
		}
		s.result.Navigations = append(s.result.Navigations, redactURL(event.Frame.URL))
		s.result.FinalURL = event.Frame.URL
		s.result.FinalOrigin = originOf(event.Frame.URL)
		s.addEvent("navigation", event.Frame.URL, "main frame")
		if len(s.result.Navigations) > s.maxNavigations {
			s.blockedError = ErrNavigationLimit
			_ = client.send("Page.stopLoading", map[string]any{})
		}
	case "Runtime.consoleAPICalled":
		if s.result.Marker == "" {
			return
		}
		if strings.Contains(string(params), s.result.Marker) {
			s.markerObserved = true
			s.addEvent("marker_observed", "", "console marker")
		}
	}
}

type cdpTarget struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

type cdpVersion struct {
	Browser string `json:"Browser"`
}

type cdpError struct {
	Message string `json:"message"`
}

type cdpMessage struct {
	ID     int             `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *cdpError       `json:"error,omitempty"`
}

type cdpClient struct {
	conn  *websocket.Conn
	state *runState
	mu    sync.Mutex
	next  int
}

func (c *cdpClient) send(method string, params any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	payload, err := json.Marshal(map[string]any{"id": c.next, "method": method, "params": params})
	if err != nil {
		return err
	}
	_, err = c.conn.Write(payload)
	return err
}

func (c *cdpClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	c.next++
	id := c.next
	payload, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err == nil {
		_, err = c.conn.Write(payload)
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		var message cdpMessage
		if err := websocket.JSON.Receive(c.conn, &message); err != nil {
			if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
				continue
			}
			return nil, err
		}
		if message.Method != "" {
			c.state.handle(message.Method, message.Params, c)
			continue
		}
		if message.ID != id {
			continue
		}
		if message.Error != nil {
			return nil, errors.New(message.Error.Message)
		}
		return message.Result, nil
	}
}

func (c *cdpClient) waitForLoad(ctx context.Context, timeout time.Duration) error {
	loadCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if err := loadCtx.Err(); err != nil {
			return err
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		var message cdpMessage
		if err := websocket.JSON.Receive(c.conn, &message); err != nil {
			if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
				continue
			}
			return err
		}
		if message.Method == "" {
			continue
		}
		c.state.handle(message.Method, message.Params, c)
		if message.Method == "Page.loadEventFired" {
			return nil
		}
	}
}

func (c *cdpClient) evaluate(ctx context.Context, expression string) (string, error) {
	result, err := c.call(ctx, "Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true, "awaitPromise": true})
	if err != nil {
		return "", err
	}
	var response struct {
		Result struct {
			Value any    `json:"value"`
			Type  string `json:"type"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return "", err
	}
	if response.Result.Value == nil {
		return "", nil
	}
	return fmt.Sprint(response.Result.Value), nil
}

func waitForVersion(ctx context.Context, port int) (cdpVersion, error) {
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/json/version", port)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for {
		if err := ctx.Err(); err != nil {
			return cdpVersion{}, fmt.Errorf("%w: %v", ErrBrowserUnavailable, err)
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		response, err := client.Do(request)
		if err == nil {
			var version cdpVersion
			decodeErr := json.NewDecoder(response.Body).Decode(&version)
			_ = response.Body.Close()
			if decodeErr == nil {
				return version, nil
			}
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return cdpVersion{}, fmt.Errorf("%w: %v", ErrBrowserUnavailable, ctx.Err())
		case <-timer.C:
		}
	}
}

func openTarget(ctx context.Context, port int) (cdpTarget, error) {
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/json/new?about:blank", port)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, nil)
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		return cdpTarget{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return cdpTarget{}, fmt.Errorf("open browser target: HTTP %d", response.StatusCode)
	}
	var target cdpTarget
	if err := json.NewDecoder(response.Body).Decode(&target); err != nil {
		return cdpTarget{}, err
	}
	if target.WebSocketDebuggerURL == "" {
		return cdpTarget{}, errors.New("browser target has no debugger websocket")
	}
	return target, nil
}

func discoverExecutable(configured string) (string, error) {
	if configured != "" {
		if _, err := os.Stat(configured); err == nil {
			return configured, nil
		}
		return "", fmt.Errorf("%w: %s", ErrBrowserUnavailable, configured)
	}
	candidates := []string{"chromium", "chromium-browser", "google-chrome", "chrome", "msedge", "chromium.exe", "chrome.exe", "msedge.exe"}
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	for _, candidate := range []string{
		os.Getenv("CHROME_PATH"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Google", "Chrome", "Application", "chrome.exe"),
	} {
		if candidate != "" {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}
	return "", ErrBrowserUnavailable
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func normalizeOrigins(origins []string) []string {
	result := make([]string, 0, len(origins))
	seen := make(map[string]bool, len(origins))
	for _, raw := range origins {
		origin := originOf(raw)
		if origin != "" && !seen[origin] {
			seen[origin] = true
			result = append(result, origin)
		}
	}
	return result
}

func originAllowed(rawURL string, allowed []string) bool {
	if rawURL == "about:blank" {
		return true
	}
	origin := originOf(rawURL)
	if origin == "" {
		return false
	}
	for _, candidate := range allowed {
		if origin == originOf(candidate) {
			return true
		}
	}
	return false
}

func originOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" || (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Hostname())
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Hostname()) + ":" + port
}

func redactURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := parsed.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || lower == "key" {
			query.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func truncate(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "…"
}

var sensitiveTextPattern = regexp.MustCompile(`(?i)((?:"|'|\b)(?:token|secret|password|api[_-]?key|authorization)(?:"|'|\b)\s*[:=]\s*["']?)[^"'\s,;<>]+`)

func redactText(value string) string {
	return sensitiveTextPattern.ReplaceAllString(value, "${1}[REDACTED]")
}

// RedactURL and RedactText expose the same masking used by the runner so
// callers storing browser observations can apply it to derived evidence too.
func RedactURL(rawURL string) string { return redactURL(rawURL) }

func RedactText(value string) string { return redactText(value) }
