// Package server is the headless listener: it does exactly one thing —
// accept captured requests from the extension and append them to the NDJSON
// log. No dashboard, no repeater, no read endpoints. Everything you'd want
// to DO with the captures (view, export, probe, authz-test) is a separate
// `hark` subcommand that reads the file. This is deliberate:
//
//   - the daemon holds live auth tokens; the fewer ways to read them back
//     over HTTP, the smaller the attack surface. There is no GET that
//     returns captures, so a malicious web page can't exfiltrate your log.
//   - POST /capture is gated by a shared token the page can't see, so a
//     random site you browse can't forge captures into your log either.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"

	"hark/store"
)

type Server struct {
	Store *store.Store
	Token string // required on /capture via X-Hark-Token; empty disables the check
	mux   *http.ServeMux
}

func New(st *store.Store, token string) *Server {
	s := &Server{Store: st, Token: token, mux: http.NewServeMux()}
	s.mux.HandleFunc("/capture", s.handleCapture)
	s.mux.HandleFunc("/health", s.handleHealth)
	return s
}

func (s *Server) Handler() http.Handler { return withCORS(s.mux) }

// CORS is required because the extension's JSON POST triggers a preflight.
// We reflect the caller's origin (the extension's chrome-extension:// origin
// isn't known ahead of time) and advertise the custom token header — but
// note there is no readable data behind any GET, so reflecting the origin
// here does not expose captures. The token, not CORS, is the real gate.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Hark-Token")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authed(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	got := r.Header.Get("X-Hark-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) == 1
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authed(r) {
		http.Error(w, "bad or missing X-Hark-Token", http.StatusUnauthorized)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20)) // 8MB hard cap per POST
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var e store.Entry
	if err := json.Unmarshal(body, &e); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	e.Source = "capture"
	saved := s.Store.Add(&e)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": saved.ID, "count": saved.Count})
}

// handleHealth is intentionally the only GET, and it returns no capture data —
// just liveness and a count, so the extension popup can show a green dot.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "entries": s.Store.Count()})
}
