package application

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/brg444/arkade-vault-server/internal/apperr"
	"github.com/brg444/arkade-vault-server/internal/program"
)

const GatewaySecretHeader = "X-Vault-Gateway-Secret"

const maxJSONBody = 1 << 20
const EnrollmentTokenHeader = "X-Vault-Enrollment-Token"

const (
	publishOperationTimeout = 55 * time.Second
	serverWriteTimeout      = 75 * time.Second
)

// NewServer wraps h with the POC listen timeouts.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// A publish operation has its own 55-second deadline. Leave a bounded
		// response margin above it for error serialization and slow clients.
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  60 * time.Second,
	}
}

// ContentSecurityPolicy is the page policy for the decrypt-and-sign UI.
// Remote script and connect sources are forbidden so a CDN cannot see the
// PRF-unlocked PhoneRoutineBIP340 software key.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; worker-src 'none'"

// Handler is the public POC HTTP API. It never proxies /v1/onchain-tx.
// Demo routes are absent unless NewHandler is given a non-nil Demo.
func Handler(svc *Service, webDir string) http.Handler {
	return NewHandler(svc, webDir, nil)
}

// AuthorizerHandler is the protected software-box surface. It deliberately
// has no static file handler, demo controller, or raw signing route.
func AuthorizerHandler(svc *Service) http.Handler {
	return requireGatewaySecret(authorizerSurface(svc))
}

func authorizerSurface(svc *Service) http.Handler {
	origin := serviceOrigin(svc)
	mux := http.NewServeMux()
	attachCoreRoutes(mux, svc, origin)
	inner := withRequestLog(withCORS(mux, origin))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods, known := authorizerRouteMethods[r.URL.Path]
		if !known {
			http.NotFound(w, r)
			return
		}
		if _, allowed := methods[r.Method]; !allowed {
			w.Header().Set("Allow", strings.Join(sortedMethods(methods), ", "))
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func safeVaultID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 80 {
		return ""
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return ""
		}
	}
	return id
}

func withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if id == "" {
			id = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		w.Header().Set("X-Request-Id", id)
		rec := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		vault := safeVaultID(r.URL.Query().Get("vault"))
		if vault == "" {
			vault = "-"
		}
		code := strings.TrimSpace(rec.Header().Get("X-Vault-Error-Code"))
		if code == "" {
			code = "ok"
		}
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("request id=%s op=%s path=%s vault=%s status=%d code=%s", id, r.Method, r.URL.Path, vault, status, code)
	})
}

func requireGatewaySecret(next http.Handler) http.Handler {
	return requireGatewaySecretValue(strings.TrimSpace(os.Getenv("VAULT_GATEWAY_SECRET")), next)
}

func requireGatewaySecretValue(want string, next http.Handler) http.Handler {
	want = strings.TrimSpace(want)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}
		if want == "" {
			http.Error(w, "gateway authentication is not configured", http.StatusServiceUnavailable)
			return
		}
		got := r.Header.Get(GatewaySecretHeader)
		wantHash := sha256.Sum256([]byte(want))
		gotHash := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(wantHash[:], gotHash[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var authorizerRouteMethods = map[string]map[string]struct{}{
	"/health":               {http.MethodGet: {}},
	"/ready":                {http.MethodGet: {}},
	"/v1/status":            {http.MethodGet: {}, http.MethodOptions: {}},
	"/v1/invite":            {http.MethodGet: {}, http.MethodOptions: {}},
	"/v1/enroll/start":      {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/enroll/propose":    {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/enroll/finish":     {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/preflight":         {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/draft":             {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/bind":              {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/authorize":         {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/initiate":          {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/clawback":          {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/publish":           {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/tx":                {http.MethodGet: {}, http.MethodOptions: {}},
	"/v1/passkey/challenge": {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/passkey/binding":   {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/passkey/install":   {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/passkey/recover":   {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/map":               {http.MethodGet: {}, http.MethodPost: {}, http.MethodOptions: {}},
}

func sortedMethods(methods map[string]struct{}) []string {
	out := make([]string, 0, len(methods))
	for method := range methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}

// NewHandler builds the public API. A nil demo is fail-closed: /v1/demo/*
// is 404 and never reaches Bitcoin RPC.
func NewHandler(svc *Service, webDir string, demo *Demo) http.Handler {
	origin := serviceOrigin(svc)
	mux := http.NewServeMux()
	attachCoreRoutes(mux, svc, origin)
	attachRegisterRoute(mux, svc, origin)
	if demo != nil {
		demo.attach(mux, origin)
	} else {
		mux.HandleFunc("/v1/demo/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "404 page not found", http.StatusNotFound)
		})
	}
	if webDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(webDir)))
	}
	return withCORS(mux, origin)
}

func serviceOrigin(svc *Service) string {
	if svc == nil {
		return program.RegtestOrigin
	}
	return svc.runtimeConfig().ClientOrigin
}

func attachCoreRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		st := svc.Ready()
		if !st.Ok {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		writeJSON(w, st, nil)
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		vaultID := strings.TrimSpace(r.URL.Query().Get("vault"))
		if vaultID == "" {
			st, err := svc.PublicStatus()
			writeJSON(w, st, err)
			return
		}
		st, err := svc.StatusFor(r.Context(), vaultID)
		writeJSON(w, st, err)
	})
	mux.HandleFunc("GET /v1/invite", func(w http.ResponseWriter, r *http.Request) {
		view, err := svc.InviteStatus(r.Header.Get(EnrollmentTokenHeader))
		writeJSON(w, view, err)
	})
	mux.HandleFunc("POST /v1/enroll/start", func(w http.ResponseWriter, r *http.Request) {
		var req EnrollStartRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		out, err := svc.StartEnrollment(r.Header.Get(EnrollmentTokenHeader))
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/enroll/propose", func(w http.ResponseWriter, r *http.Request) {
		var req EnrollFinishRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		out, err := svc.ProposeEnrollment(r.Header.Get(EnrollmentTokenHeader), req)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/enroll/finish", func(w http.ResponseWriter, r *http.Request) {
		var req EnrollFinishRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		out, err := svc.FinishEnrollment(r.Context(), r.Header.Get(EnrollmentTokenHeader), req)
		writeJSON(w, out, err)
	})
	attachSpendRoutes(mux, svc, origin)
}

func attachSpendRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/preflight", func(w http.ResponseWriter, r *http.Request) {
		var req PreflightRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		resp, err := svc.PreflightRequestContext(r.Context(), req)
		writeJSON(w, resp, err)
	})
	mux.HandleFunc("POST /v1/draft", func(w http.ResponseWriter, r *http.Request) {
		var req DraftRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		psbt, err := svc.DraftContext(r.Context(), req)
		writeJSON(w, map[string]any{"psbt": psbt}, err)
	})
	mux.HandleFunc("POST /v1/bind", func(w http.ResponseWriter, r *http.Request) {
		var req BindRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		psbt, err := svc.BindContext(r.Context(), req)
		writeJSON(w, map[string]any{"psbt": psbt}, err)
	})
	mux.HandleFunc("POST /v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var req AuthorizeRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		signed, replay, err := svc.Authorize(r.Context(), req)
		writeJSON(w, map[string]any{"signedPsbt": signed, "replay": replay}, err)
	})
	mux.HandleFunc("POST /v1/initiate", func(w http.ResponseWriter, r *http.Request) {
		var req TransitionRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		req.Purpose = "initiate"
		out, err := svc.SignTransition(r.Context(), req)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/clawback", func(w http.ResponseWriter, r *http.Request) {
		var req TransitionRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		req.Purpose = "clawback"
		out, err := svc.SignTransition(r.Context(), req)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/publish", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			VaultID   string `json:"vaultId"`
			Challenge string `json:"challenge"`
		}
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		opCtx, cancel := context.WithTimeout(r.Context(), publishOperationTimeout)
		defer cancel()
		out, err := svc.PublishVault(opCtx, req.VaultID, req.Challenge)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/passkey/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req PasskeyChallengeRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		out, err := svc.IssuePasskeyChallengeFor(r.Context(), req.VaultID, req.Purpose)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/passkey/binding", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			VaultID string `json:"vaultId"`
			RecoveryBindingRequest
		}
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		out, err := svc.BuildRecoveryBindingFor(req.VaultID, req.RecoveryBindingRequest)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/passkey/install", func(w http.ResponseWriter, r *http.Request) {
		var req InstallCredentialEnvelopeRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		err := svc.InstallCredentialEnvelope(r.Context(), req)
		writeJSON(w, map[string]any{"ok": err == nil}, err)
	})
	mux.HandleFunc("POST /v1/passkey/recover", func(w http.ResponseWriter, r *http.Request) {
		var req RecoverCredentialEnvelopeRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		out, err := svc.RecoverCredentialEnvelope(r.Context(), req)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("GET /v1/map", func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.GetMap(r.URL.Query().Get("vault"))
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/map", func(w http.ResponseWriter, r *http.Request) {
		var req MapWriteRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		err := svc.PutMap(r.Context(), req)
		writeJSON(w, map[string]any{"ok": err == nil}, err)
	})
	mux.HandleFunc("GET /v1/tx", func(w http.ResponseWriter, r *http.Request) {
		opCtx, cancel := context.WithTimeout(r.Context(), publishOperationTimeout)
		defer cancel()
		out, err := svc.PublicationStatusVault(opCtx, r.URL.Query().Get("vaultId"), r.URL.Query().Get("challenge"))
		writeJSON(w, out, err)
	})
}

type mutationError struct {
	status int
	msg    string
}

func (e *mutationError) Error() string { return e.msg }

func decodeMutation(r *http.Request, dst any, expectedOrigin string) error {
	ct := r.Header.Get("Content-Type")
	if ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		return &mutationError{http.StatusUnsupportedMediaType, "content-type"}
	}
	if expectedOrigin == "" || r.Header.Get("Origin") != expectedOrigin {
		return &mutationError{http.StatusForbidden, "origin"}
	}
	if r.ContentLength > maxJSONBody {
		return &mutationError{http.StatusRequestEntityTooLarge, "request too large"}
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("multiple json values")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("multiple json values")
	}
	return nil
}

func writeMutationError(w http.ResponseWriter, err error) {
	var me *mutationError
	if errors.As(err, &me) {
		http.Error(w, me.msg, me.status)
		return
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		status := http.StatusBadRequest
		code := apperr.CodeRejected
		switch {
		case errors.Is(err, ErrEnrollmentClosed), errors.Is(err, apperr.ErrEnrollmentClosed), errors.Is(err, apperr.ErrNotFound):
			status = http.StatusNotFound
			code = apperr.CodeNotFound
		case errors.Is(err, ErrVerificationBusy), errors.Is(err, apperr.ErrBusy):
			status = http.StatusTooManyRequests
			code = apperr.CodeBusy
			w.Header().Set("Retry-After", "1")
		case errors.Is(err, apperr.ErrVaultIDRequired):
			code = apperr.CodeVaultIDRequired
		case errors.Is(err, apperr.ErrNotEnrolled):
			code = apperr.CodeNotEnrolled
		case errors.Is(err, apperr.ErrLegacyMasterSign):
			code = apperr.CodeLegacyMasterSign
		default:
			if e := apperr.Of(err); e != nil && e.Code != apperr.CodeRejected {
				code = e.Code
			}
		}
		w.Header().Set("X-Vault-Error-Code", string(code))
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": publicErrorMessage(err), "code": string(code)})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func publicErrorMessage(err error) string {
	if err == nil {
		return "request rejected"
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	for _, leak := range []string{
		"http ", "esplora", "sqlite", "sql:", "public arkade", "/app/",
		"panic", "stack", "goroutine", "\n",
	} {
		if strings.Contains(lower, leak) {
			return "request rejected"
		}
	}
	return msg
}

func withCORS(next http.Handler, origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, "+EnrollmentTokenHeader)
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Never serve a generic emulator signing path.
		if strings.HasPrefix(r.URL.Path, "/v1/onchain-tx") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
