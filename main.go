package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

type KeyLimit map[string]int

type SiteConfig struct {
	Domain    string     `json:"domain"`
	ProxyType string     `json:"PROXY_TYPE,omitempty"`
	Key       string     `json:"KEY,omitempty"`
	Values    []KeyLimit `json:"VALUES,omitempty"`
}

type GlobalSettings struct {
	DirectAccess bool     `json:"DIRECT_ACCESS"`
	BasePath     string   `json:"BASE_PATH"`
	Proxies      []string `json:"PROXIES"`
}

type Config struct {
	GlobalSettings GlobalSettings        `json:"GLOBAL_SETTINGS"`
	Sites          map[string]SiteConfig `json:"SITES"`
}

type RateLimiter struct {
	limit     int
	requests  int
	lastReset time.Time
	mu        sync.Mutex
}

type ClientWrapper struct {
	Client   *http.Client
	IsDirect bool
}

type KeyLimiter struct {
	Key     string
	Limiter *RateLimiter
}

type SiteHandler struct {
	config  SiteConfig
	apiKeys []KeyLimiter
	index   atomic.Int32
	mu      sync.RWMutex
}

type ProxyServer struct {
	config      Config
	clients     []ClientWrapper
	sites       map[string]*SiteHandler
	clientIndex atomic.Int32
}

func NewRateLimiter(rps int) *RateLimiter {
	return &RateLimiter{
		limit:     rps,
		lastReset: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.lastReset) >= time.Second {
		rl.requests = 0
		rl.lastReset = now
	}

	if rl.limit > 0 && rl.requests >= rl.limit {
		return false
	}

	rl.requests++
	return true
}

func createProxyClient(proxyURL string) (*http.Client, error) {
	urlParsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	var transport *http.Transport
	switch urlParsed.Scheme {
	case "socks5", "socks5h":
		auth := &proxy.Auth{
			User: urlParsed.User.Username(),
		}
		if password, ok := urlParsed.User.Password(); ok {
			auth.Password = password
		}

		dialer, err := proxy.SOCKS5("tcp", urlParsed.Host, auth, &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		})
		if err != nil {
			return nil, err
		}

		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}

	case "http", "https":
		transport = &http.Transport{
			Proxy: http.ProxyURL(urlParsed),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", urlParsed.Scheme)
	}

	// Enable HTTP/2 support for the transport
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, fmt.Errorf("failed to configure HTTP/2: %v", err)
	}

	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func NewProxyServer(configPath string) (*ProxyServer, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	// Validate site configurations
	for siteName, siteConfig := range config.Sites {
		allowedProxyTypes := map[string]bool{"header": true, "query": true, "path": true, "direct": true}
		if !allowedProxyTypes[siteConfig.ProxyType] {
			return nil, fmt.Errorf("invalid PROXY_TYPE %s for site %s", siteConfig.ProxyType, siteName)
		}

		if siteConfig.ProxyType == "direct" {
			for _, keyLimit := range siteConfig.Values {
				for key := range keyLimit {
					if _, err := url.Parse(key); err != nil {
						return nil, fmt.Errorf("invalid URL in direct proxy VALUES for site %s: %v", siteName, key)
					}
				}
			}
		} else if (siteConfig.ProxyType == "header" || siteConfig.ProxyType == "query") && siteConfig.Key == "" {
			return nil, fmt.Errorf("PROXY_TYPE %s requires KEY for site %s", siteConfig.ProxyType, siteName)
		}
	}

	server := &ProxyServer{
		config:  config,
		clients: make([]ClientWrapper, 0),
		sites:   make(map[string]*SiteHandler),
	}

	// Initialize site handlers
	for siteName, siteConfig := range config.Sites {
		handler := &SiteHandler{
			config:  siteConfig,
			apiKeys: make([]KeyLimiter, 0),
		}

		if len(siteConfig.Values) > 0 && (siteConfig.ProxyType == "path" || siteConfig.ProxyType == "direct" || siteConfig.Key != "") {
			for _, keyLimit := range siteConfig.Values {
				for key, limit := range keyLimit {
					handler.apiKeys = append(handler.apiKeys, KeyLimiter{
						Key:     key,
						Limiter: NewRateLimiter(limit),
					})
				}
			}
		}

		server.sites[siteName] = handler
	}

	// Initialize direct client if enabled
	if config.GlobalSettings.DirectAccess {
		transport := &http.Transport{}
		if err := http2.ConfigureTransport(transport); err != nil {
			log.Printf("Failed to configure HTTP/2 for direct client: %v", err)
		}
		server.clients = append(server.clients, ClientWrapper{
			Client:   &http.Client{Transport: transport, Timeout: 30 * time.Second},
			IsDirect: true,
		})
	}

	// Initialize proxy clients
	for _, proxyURL := range config.GlobalSettings.Proxies {
		client, err := createProxyClient(proxyURL)
		if err != nil {
			log.Printf("Failed to create proxy client for %s: %v", proxyURL, err)
			continue
		}
		server.clients = append(server.clients, ClientWrapper{
			Client:   client,
			IsDirect: false,
		})
	}

	// Ensure at least one client is available
	if len(server.clients) == 0 {
		return nil, fmt.Errorf("no working clients available")
	}

	return server, nil
}

func (s *ProxyServer) getNextClient() *ClientWrapper {
	currentIndex := int(s.clientIndex.Add(1)) % len(s.clients)
	return &s.clients[currentIndex]
}

func (h *SiteHandler) getAvailableKey() string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.apiKeys) == 0 {
		return ""
	}

	start := h.index.Add(1) % int32(len(h.apiKeys))
	for i := 0; i < len(h.apiKeys); i++ {
		idx := (start + int32(i)) % int32(len(h.apiKeys))
		keyLimiter := h.apiKeys[idx]
		if keyLimiter.Limiter.Allow() {
			h.index.Store(idx)
			return keyLimiter.Key
		}
	}
	return ""
}

func (s *ProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Api-Key, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	basePath := s.config.GlobalSettings.BasePath
	if basePath == "" {
		basePath = "/proxy"
	}
	basePath = "/" + strings.Trim(basePath, "/")

	if !strings.HasPrefix(r.URL.Path, basePath) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	remainingPath := strings.TrimPrefix(r.URL.Path, basePath)
	remainingPath = strings.Trim(remainingPath, "/")

	parts := strings.SplitN(remainingPath, "/", 2)
	if len(parts) < 1 {
		http.Error(w, "Invalid path format", http.StatusBadRequest)
		return
	}

	siteName := parts[0]
	actualPath := "/"
	if len(parts) > 1 {
		actualPath = "/" + parts[1]
	}

	siteHandler, exists := s.sites[siteName]
	if !exists {
		http.Error(w, fmt.Sprintf("Site %s not found", siteName), http.StatusNotFound)
		return
	}

	var apiKey string
	if len(siteHandler.config.Values) > 0 && (siteHandler.config.ProxyType == "path" || siteHandler.config.ProxyType == "direct" || siteHandler.config.Key != "") {
		apiKey = siteHandler.getAvailableKey()
		if apiKey == "" {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}

	client := s.getNextClient()

	var targetURL *url.URL
	var err error

	if siteHandler.config.ProxyType == "direct" {
		targetURL, err = url.Parse(apiKey)
		if err != nil {
			log.Printf("Failed to parse direct URL %s: %v", apiKey, err)
			http.Error(w, "Invalid target URL", http.StatusInternalServerError)
			return
		}
		targetURL.Path = path.Join(targetURL.Path, actualPath)
	} else {
		targetURL, err = url.Parse(siteHandler.config.Domain)
		if err != nil {
			log.Printf("Failed to parse domain %s: %v", siteHandler.config.Domain, err)
			http.Error(w, "Invalid target URL", http.StatusInternalServerError)
			return
		}

		domainPath := targetURL.Path
		switch siteHandler.config.ProxyType {
		case "path":
			if apiKey != "" {
				if siteHandler.config.Key == "" {
					targetURL.Path = path.Join(domainPath, apiKey, actualPath)
				} else {
					targetURL.Path = path.Join(domainPath, actualPath)
				}
			} else {
				targetURL.Path = path.Join(domainPath, actualPath)
			}
		default:
			targetURL.Path = path.Join(domainPath, actualPath)
		}
	}

	targetURL.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		if siteHandler.config.Key == "" || !strings.EqualFold(key, siteHandler.config.Key) {
			for _, value := range values {
				outReq.Header.Add(key, value)
			}
		}
	}

	if apiKey != "" && siteHandler.config.ProxyType != "direct" {
		switch siteHandler.config.ProxyType {
		case "header":
			outReq.Header.Set(siteHandler.config.Key, apiKey)
		case "query":
			q := outReq.URL.Query()
			q.Set(siteHandler.config.Key, apiKey)
			outReq.URL.RawQuery = q.Encode()
		case "path":
		default:
			log.Printf("Unknown PROXY_TYPE: %s", siteHandler.config.ProxyType)
		}
	}

	headersToRemove := []string{
		"geoip2-COUNTRY-CODE",
		"geoip2-COUNTRY-NAME",
		"geoip2-CITY-NAME",
		"geoip2-ASN-CODE",
		"geoip2-IP-Address",
		"X-Real-IP",
		"X-Forwarded-For",
		"X-Forwarded-Proto",
		"X-Forwarded-Scheme",
		"CF-Connecting-IP",
		"CF-Connecting-IPv6",
		"CF-Pseudo-IPv4",
		"True-Client-IP",
		"CF-RAY",
		"CF-IPCountry",
		"CF-Visitor",
		"CDN-Loop",
		"CF-Worker",
	}

	for _, header := range headersToRemove {
		outReq.Header.Del(header)
	}

	//outReq.Header.Set("Accept", "application/json")
	//outReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Client.Do(outReq)
	if err != nil {
		log.Printf("Request to %s failed: %v", targetURL.String(), err)
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("Failed to close response body: %v", err)
		}
	}(resp.Body)

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Failed to stream response: %v", err)
	}
}

func main() {
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	server, err := NewProxyServer(configPath)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	http.HandleFunc("/", server.handleRequest)

	log.Printf("Starting proxy server on :3000")

	srv := &http.Server{
		Addr:    ":3000",
		Handler: nil,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
}
