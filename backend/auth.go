package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	bootstrapTokenFile = "bootstrap-token"
	adminFile          = "admin.json"
	sessionCookie      = "inextos_clash_session"
	sessionLifetime    = 12 * time.Hour
	argonTime          = uint32(3)
	argonMemory        = uint32(64 * 1024)
	argonThreads       = uint8(4)
)

var administratorName = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)

func publicAccess(r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") || strings.TrimSpace(r.Header.Get("X-Forwarded-Host")) == "" {
		return false
	}
	ip := net.ParseIP(remoteIP(r.RemoteAddr))
	return ip != nil && ip.IsLoopback()
}

type authManager struct {
	stateDir  string
	mu        sync.Mutex
	hashMu    sync.Mutex
	attemptMu sync.Mutex
	sessions  map[string]time.Time
	failures  map[string]loginFailure
}

type accessScopeKey struct{}

func handlerForScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accessScopeKey{}, scope)))
	})
}

func requestAccessScope(r *http.Request) string {
	scope, _ := r.Context().Value(accessScopeKey{}).(string)
	return scope
}

type loginFailure struct {
	count        int
	blockedUntil time.Time
}

type adminCredential struct {
	Username string `json:"username"`
	Scheme   string `json:"scheme"`
	Salt     string `json:"salt"`
	Hash     string `json:"hash"`
	Time     uint32 `json:"time"`
	Memory   uint32 `json:"memory_kib"`
	Threads  uint8  `json:"threads"`
}

func newAuthManager(stateDir string) *authManager {
	return &authManager{stateDir: stateDir, sessions: make(map[string]time.Time), failures: make(map[string]loginFailure)}
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func sessionDigest(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (a *authManager) initialized() bool {
	_, err := os.Stat(filepath.Join(a.stateDir, adminFile))
	return err == nil
}

func (a *authManager) setupOpen() (time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.initialized() {
		return time.Time{}, errors.New("administrator already exists")
	}
	expires := time.Now().Add(10 * time.Minute)
	path := filepath.Join(a.stateDir, "setup-open")
	if err := atomicWrite(path, []byte(expires.UTC().Format(time.RFC3339Nano)+"\n"), 0600); err != nil {
		return time.Time{}, err
	}
	if err := chownLikeDir(path, a.stateDir); err != nil {
		return time.Time{}, err
	}
	return expires, os.Chmod(path, 0640)
}

func chownLikeDir(path, dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("could not determine state owner")
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}

func (a *authManager) publicSetupAllowed() bool {
	b, err := os.ReadFile(filepath.Join(a.stateDir, "setup-open"))
	if err != nil {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	return err == nil && time.Now().Before(expires) && !a.initialized()
}

func validAdminPassword(password string) bool {
	return utf8.RuneCountInString(password) >= 8 && len(password) <= 1024
}

func (a *authManager) setup(username, password string) error {
	if !administratorName.MatchString(username) {
		return errors.New("username must be 3-32 letters, numbers, dot, underscore or hyphen")
	}
	if !validAdminPassword(password) {
		return errors.New("password must be at least 8 characters and no more than 1024 bytes")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	adminPath := filepath.Join(a.stateDir, adminFile)
	if _, err := os.Stat(adminPath); err == nil {
		return errors.New("administrator is already initialized")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	a.hashMu.Lock()
	credential, err := hashPassword(password)
	a.hashMu.Unlock()
	if err != nil {
		return err
	}
	credential.Username = username
	data, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	if err := atomicWrite(adminPath, append(data, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(a.stateDir, bootstrapTokenFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(filepath.Join(a.stateDir, "setup-open"))
	return nil
}

func (a *authManager) credential() (adminCredential, error) {
	b, err := os.ReadFile(filepath.Join(a.stateDir, adminFile))
	if err != nil {
		return adminCredential{}, err
	}
	var credential adminCredential
	err = json.Unmarshal(b, &credential)
	if err == nil && credential.Username == "" {
		credential.Username = "admin"
		migrated, marshalErr := json.Marshal(credential)
		if marshalErr != nil {
			return adminCredential{}, marshalErr
		}
		if writeErr := atomicWrite(filepath.Join(a.stateDir, adminFile), append(migrated, '\n'), 0600); writeErr != nil {
			return adminCredential{}, writeErr
		}
	}
	return credential, err
}

func (a *authManager) update(username, oldPassword, newPassword string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	credential, err := a.credential()
	if err != nil {
		return err
	}
	if !administratorName.MatchString(username) {
		return errors.New("invalid username")
	}
	if newPassword != "" && !validAdminPassword(newPassword) {
		return errors.New("password must be at least 8 characters")
	}
	a.hashMu.Lock()
	ok := verifyPassword(credential, oldPassword)
	if !ok {
		a.hashMu.Unlock()
		return errors.New("current password is incorrect")
	}
	if newPassword != "" {
		credential, err = hashPassword(newPassword)
	}
	a.hashMu.Unlock()
	if err != nil {
		return err
	}
	credential.Username = username
	b, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	path := filepath.Join(a.stateDir, adminFile)
	if err := atomicWrite(path, append(b, '\n'), 0600); err != nil {
		return err
	}
	if err := chownLikeDir(path, a.stateDir); err != nil {
		return err
	}
	a.sessions = make(map[string]time.Time)
	return nil
}

func (a *authManager) resetPassword(password string) error {
	if !validAdminPassword(password) {
		return errors.New("password must be at least 8 characters")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	old, err := a.credential()
	if err != nil {
		return err
	}
	a.hashMu.Lock()
	credential, err := hashPassword(password)
	a.hashMu.Unlock()
	if err != nil {
		return err
	}
	credential.Username = old.Username
	b, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	path := filepath.Join(a.stateDir, adminFile)
	if err := atomicWrite(path, append(b, '\n'), 0600); err != nil {
		return err
	}
	if err := chownLikeDir(path, a.stateDir); err != nil {
		return err
	}
	a.sessions = make(map[string]time.Time)
	return nil
}

func hashPassword(password string) (adminCredential, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return adminCredential{}, err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, 32)
	return adminCredential{
		Scheme: "argon2id", Salt: base64.RawStdEncoding.EncodeToString(salt),
		Hash: base64.RawStdEncoding.EncodeToString(hash), Time: argonTime,
		Memory: argonMemory, Threads: argonThreads,
	}, nil
}

func verifyPassword(credential adminCredential, password string) bool {
	if credential.Scheme != "argon2id" || credential.Time != argonTime || credential.Memory != argonMemory || credential.Threads != argonThreads {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(credential.Salt)
	if err != nil || len(salt) != 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(credential.Hash)
	if err != nil || len(expected) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, credential.Time, credential.Memory, credential.Threads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func (a *authManager) login(ip, username, password string) (string, time.Duration, error) {
	a.attemptMu.Lock()
	defer a.attemptMu.Unlock()
	if wait := a.loginWait(ip, time.Now()); wait > 0 {
		return "", wait, errors.New("too many failed attempts")
	}
	credential, err := a.credential()
	if err != nil {
		return "", 0, errors.New("administrator is not initialized")
	}
	a.hashMu.Lock()
	ok := verifyPassword(credential, password)
	a.hashMu.Unlock()
	if !ok || !strings.EqualFold(credential.Username, username) {
		a.failedLogin(ip, time.Now())
		return "", 0, errors.New("用户名或密码错误")
	}
	a.resetLoginFailures(ip)
	token, err := randomToken()
	if err != nil {
		return "", 0, err
	}
	a.mu.Lock()
	for key, expiry := range a.sessions {
		if !time.Now().Before(expiry) {
			delete(a.sessions, key)
		}
	}
	a.sessions[sessionDigest(token)] = time.Now().Add(sessionLifetime)
	a.mu.Unlock()
	return token, 0, nil
}

func (a *authManager) loginWait(ip string, now time.Time) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := a.failures[ip]
	if now.Before(entry.blockedUntil) {
		return entry.blockedUntil.Sub(now)
	}
	if !entry.blockedUntil.IsZero() {
		delete(a.failures, ip)
	}
	return 0
}

func (a *authManager) failedLogin(ip string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := a.failures[ip]
	entry.count++
	if entry.count >= 5 {
		entry.count = 0
		entry.blockedUntil = now.Add(5 * time.Minute)
	}
	a.failures[ip] = entry
	if len(a.failures) > 1024 {
		for key, item := range a.failures {
			if !now.Before(item.blockedUntil) {
				delete(a.failures, key)
			}
		}
	}
}

func (a *authManager) resetLoginFailures(ip string) {
	a.mu.Lock()
	delete(a.failures, ip)
	a.mu.Unlock()
}

func (a *authManager) authenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	key := sessionDigest(cookie.Value)
	a.mu.Lock()
	defer a.mu.Unlock()
	expires, ok := a.sessions[key]
	if !ok {
		return false
	}
	if !time.Now().Before(expires) {
		delete(a.sessions, key)
		return false
	}
	return true
}

func (a *authManager) logout(r *http.Request) {
	cookie, err := r.Cookie(sessionCookie)
	if err == nil {
		a.mu.Lock()
		delete(a.sessions, sessionDigest(cookie.Value))
		a.mu.Unlock()
	}
}

func (a *API) authStatus(w http.ResponseWriter, r *http.Request) {
	initialized := a.auth.initialized()
	setupAllowed := !initialized && (requestAccessScope(r) == "lan" || requestAccessScope(r) == "loopback")
	if !initialized && publicAccess(r) {
		setupAllowed = a.auth.publicSetupAllowed()
	}
	writeJSON(w, http.StatusOK, map[string]bool{"initialized": initialized, "setup_allowed": setupAllowed})
}

func (a *API) authSetup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &input, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	if a.auth.initialized() {
		writeError(w, http.StatusConflict, "administrator is already initialized")
		return
	}
	scope := requestAccessScope(r)
	if publicAccess(r) {
		scope = "public_https"
	}
	if scope != "lan" && scope != "loopback" && scope != "public_https" {
		writeError(w, http.StatusForbidden, "setup is only available on a trusted LAN or local listener")
		return
	}
	if scope == "public_https" && !a.auth.publicSetupAllowed() {
		writeError(w, http.StatusForbidden, "初始化尚未授权。请在设备终端执行 sudo inextos-clash setup-open，授权有效期 10 分钟。")
		return
	}
	sourceIP := requestClientIP(r)
	if scope == "public_https" {
		forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		if strings.Contains(forwarded, ",") || net.ParseIP(forwarded) == nil {
			writeError(w, http.StatusForbidden, "trusted proxy source address is unavailable")
			return
		}
		sourceIP = net.ParseIP(forwarded).String()
	}
	if err := a.auth.setup(input.Username, input.Password); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "already initialized") {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	if a.logger != nil {
		if scope == "loopback" {
			scope = "localhost"
		}
		a.logger.Info("administrator created", "username", input.Username, "access_scope", scope, "source_ip", sourceIP)
	}
	a.recordEvent("administrator_created")
	writeJSON(w, http.StatusCreated, map[string]bool{"initialized": true})
}

func (a *API) authLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &input, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	ip := requestClientIP(r)
	token, wait, err := a.auth.login(ip, input.Username, input.Password)
	if wait > 0 {
		a.recordEvent("login_security")
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed attempts; wait before trying again")
		return
	}
	if err != nil {
		if !a.auth.initialized() {
			writeError(w, http.StatusConflict, "administrator is not initialized")
			return
		}
		a.recordEvent("login_security")
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: isHTTPSRequest(r), SameSite: http.SameSiteLaxMode,
		MaxAge: int(sessionLifetime.Seconds()), Expires: time.Now().Add(sessionLifetime),
	})
	a.recordEvent("administrator_login")
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (a *API) authMe(w http.ResponseWriter, r *http.Request) {
	credential, err := a.auth.credential()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "administrator unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "username": credential.Username})
}

func (a *API) authAccount(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username        string `json:"username"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := decodeJSON(w, r, &input, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid account request")
		return
	}
	if input.NewPassword != input.ConfirmPassword {
		writeError(w, http.StatusBadRequest, "new passwords do not match")
		return
	}
	if err := a.auth.update(input.Username, input.CurrentPassword, input.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.recordEvent("administrator_updated")
	writeJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

func (a *API) authLogout(w http.ResponseWriter, r *http.Request) {
	a.auth.logout(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: isHTTPSRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func remoteIP(remote string) string {
	ip, _, err := net.SplitHostPort(remote)
	if err == nil {
		return ip
	}
	return remote
}

func trustedHTTPSProxy(r *http.Request) bool {
	return publicAccess(r)
}

func isHTTPSRequest(r *http.Request) bool {
	return r.TLS != nil || trustedHTTPSProxy(r)
}

func requestClientIP(r *http.Request) string {
	if trustedHTTPSProxy(r) {
		forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		if !strings.Contains(forwarded, ",") {
			if ip := net.ParseIP(forwarded); ip != nil {
				return ip.String()
			}
		}
	}
	return remoteIP(r.RemoteAddr)
}

func (a *API) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ancestors := a.frameAncestors
		if len(ancestors) == 0 {
			ancestors = []string{"'self'"}
		}
		imageSources := []string{"'self'", "data:"}
		if (r.URL.Path == "/dashboard" || strings.HasPrefix(r.URL.Path, "/dashboard/")) && a.auth != nil && a.auth.authenticated(r) && a.manager != nil {
			imageSources = append(imageSources, dashboardIconSources(a.manager.configFile)...)
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; img-src "+strings.Join(imageSources, " ")+"; style-src 'self'; frame-ancestors "+strings.Join(ancestors, " "))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		if _, ok := a.allowedHosts[strings.ToLower(r.Host)]; !ok {
			writeError(w, http.StatusForbidden, "host is not allowed")
			return
		}
		if isStateChange(r.Method) && !a.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "request origin is not allowed")
			return
		}
		if (r.URL.Path == "/dashboard" || strings.HasPrefix(r.URL.Path, "/dashboard/")) && !a.auth.authenticated(r) {
			if r.URL.Path == "/dashboard/api" || strings.HasPrefix(r.URL.Path, "/dashboard/api/") {
				writeError(w, http.StatusUnauthorized, "authentication required")
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !publicAPIRequest(r) && !a.auth.authenticated(r) {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isStateChange(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

func publicAPIRequest(r *http.Request) bool {
	switch {
	case r.URL.Path == "/api/health" && r.Method == http.MethodGet:
		return true
	case r.URL.Path == "/api/auth/status" && r.Method == http.MethodGet:
		return true
	case (r.URL.Path == "/api/auth/setup" || r.URL.Path == "/api/auth/login") && r.Method == http.MethodPost:
		return true
	default:
		return false
	}
}

func (a *API) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || r.Host == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	scheme := "http"
	host := r.Host
	if trustedHTTPSProxy(r) {
		host = r.Header.Get("X-Forwarded-Host")
	}
	if isHTTPSRequest(r) {
		scheme = "https"
	}
	return host != "" && strings.EqualFold(u.Scheme, scheme) && strings.EqualFold(u.Host, host)
}
