package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const dashboardAPIPrefix = "/dashboard/api"

func (a *API) dashboardRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	http.Redirect(w, r, "/dashboard/", http.StatusPermanentRedirect)
}

func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	root := a.activeDashboardDirectory()
	if root == "" {
		root = dashboardDir
	}
	if r.URL.Path == "/dashboard/" {
		index, err := os.ReadFile(filepath.Join(root, "index.html"))
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Zashboard is not installed")
			return
		}
		const marker = "</head>"
		if !strings.Contains(string(index), marker) {
			writeError(w, http.StatusServiceUnavailable, "Zashboard entry page is invalid")
			return
		}
		index = []byte(strings.Replace(string(index), marker, "  <script src=\"./inextos-clash-bootstrap.js\"></script>\n</head>", 1))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(index)
		}
		return
	}
	if strings.TrimPrefix(r.URL.Path, "/dashboard/") == "inextos-clash-bootstrap.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, dashboardBootstrapJS)
		return
	}
	fileServer := http.StripPrefix("/dashboard/", http.FileServer(http.Dir(root)))
	resource := strings.TrimPrefix(r.URL.Path, "/dashboard/")
	if strings.HasPrefix(resource, "assets/") && filepath.Clean(resource) == resource {
		if _, err := os.Stat(filepath.Join(root, resource)); os.IsNotExist(err) {
			if previous, err := a.dashboardInstallation("previous.json"); err == nil {
				previousRoot := a.dashboardDir
				if previous.Directory != "" {
					previousRoot = filepath.Join(a.dashboardUpdatesDir, previous.Directory)
				}
				fileServer = http.StripPrefix("/dashboard/", http.FileServer(http.Dir(previousRoot)))
			}
		}
	}
	fileServer.ServeHTTP(w, r)
}

const dashboardBootstrapJS = `(() => {
  if (window.location.hash) return;
  const protocol = window.location.protocol.slice(0, -1);
  const params = new URLSearchParams({
    protocol,
    hostname: window.location.hostname,
    port: window.location.port || (protocol === 'https' ? '443' : '80'),
    secondaryPath: '/dashboard/api',
    disableUpgradeCore: '1',
    disableTunMode: '1'
  });
  window.location.replace('/dashboard/#/setup?' + params.toString());
})();
`

func (a *API) dashboardAPI(w http.ResponseWriter, r *http.Request) {
	if !dashboardControllerRequestAllowed(w, r) {
		return
	}
	port := a.state.ControllerPort
	if port < 1 || port > 65535 {
		writeError(w, http.StatusServiceUnavailable, "Mihomo Controller is unavailable")
		return
	}
	target := &url.URL{Scheme: "http", Host: netJoinLocalhost(port)}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			escaped := strings.TrimPrefix(pr.In.URL.EscapedPath(), dashboardAPIPrefix)
			path, err := url.PathUnescape(escaped)
			if err != nil || path == "" {
				path = "/"
			}
			pr.Out.URL.Path = path
			pr.Out.URL.RawPath = escaped
			query := pr.In.URL.Query()
			query.Del("secret")
			pr.Out.URL.RawQuery = query.Encode()
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Set("Authorization", "Bearer "+a.manager.secret)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			a.logger.Warn("dashboard Controller request failed", "method", r.Method, "reason", err.Error())
			writeError(w, http.StatusBadGateway, "Mihomo Controller is unavailable")
		},
	}
	proxy.ServeHTTP(w, r)
}

func dashboardControllerRequestAllowed(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, dashboardAPIPrefix+"/") {
		writeError(w, http.StatusNotFound, "not found")
		return false
	}
	path := strings.TrimPrefix(r.URL.Path, dashboardAPIPrefix)
	for _, blocked := range []string{"/upgrade", "/tun", "/configs/geo"} {
		if path == blocked || strings.HasPrefix(path, blocked+"/") {
			writeError(w, http.StatusForbidden, "this operation is managed by Clash for iNextOS")
			return false
		}
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	switch {
	case (r.Method == http.MethodPut || r.Method == http.MethodPatch) && path == "/configs":
		return validateDashboardConfigChange(w, r)
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/proxies/") && !strings.Contains(strings.TrimPrefix(path, "/proxies/"), "/"):
		return true
	case r.Method == http.MethodDelete && (path == "/connections" || strings.HasPrefix(path, "/connections/")):
		return true
	default:
		writeError(w, http.StatusForbidden, "operation is not available through this dashboard")
		return false
	}
}

func validateDashboardConfigChange(w http.ResponseWriter, r *http.Request) bool {
	var body struct {
		Mode     *string `json:"mode"`
		LogLevel *string `json:"log-level"`
	}
	reader := http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(reader)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "only mode and log-level can be changed in Zashboard")
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) || (body.Mode == nil && body.LogLevel == nil) {
		writeError(w, http.StatusBadRequest, "invalid Mihomo settings change")
		return false
	}
	if body.Mode != nil && *body.Mode != "rule" && *body.Mode != "global" && *body.Mode != "direct" {
		writeError(w, http.StatusBadRequest, "invalid Mihomo mode")
		return false
	}
	if body.LogLevel != nil && !validMihomoLogLevel(*body.LogLevel) {
		writeError(w, http.StatusBadRequest, "invalid Mihomo log level")
		return false
	}
	return true
}

func netJoinLocalhost(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

func validMihomoLogLevel(level string) bool {
	switch level {
	case "silent", "error", "warning", "info", "debug":
		return true
	default:
		return false
	}
}
