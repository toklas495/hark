// auth.go is "autorize without Burp". It answers one question for every
// captured endpoint: if I replay this exact request as a DIFFERENT (usually
// lower-privileged) identity, does the server still let me in?
//
// The captured response is the baseline — it was recorded as whoever you were
// when you crawled (typically the privileged user). We replay each request
// with the swapped identity header(s) and compare:
//
//	ENFORCED  — replay got 401/403 (or a clear auth error). Access control works.
//	BYPASSED  — replay got the same 2xx with a near-identical body. The low-priv
//	            identity sees what the privileged one saw. This is the bug.
//	CHECK     — 2xx but the body differs a lot (could be per-user data, could be
//	            a partial leak — worth a human look).
//	UNKNOWN   — anything else (network error, 404/5xx), reported as-is.
//
// This is the same idea as Burp's Autorize, driven off your own capture log
// instead of a Burp proxy history.
package analyze

import (
	"fmt"
	"strings"

	"hark/store"
)

type AuthVerdict string

const (
	VerdictEnforced AuthVerdict = "ENFORCED"
	VerdictBypassed AuthVerdict = "BYPASSED"
	VerdictCheck    AuthVerdict = "CHECK"
	VerdictUnknown  AuthVerdict = "UNKNOWN"
)

type AuthResult struct {
	EntryID      string      `json:"entryId"`
	Method       string      `json:"method"`
	URL          string      `json:"url"`
	StatusBefore int         `json:"statusBefore"`
	StatusAfter  int         `json:"statusAfter"`
	LenBefore    int         `json:"lenBefore"`
	LenAfter     int         `json:"lenAfter"`
	Verdict      AuthVerdict `json:"verdict"`
	Note         string      `json:"note"`
	DurationMs   int64       `json:"durationMs"`
	Error        string      `json:"error,omitempty"`
}

func (r AuthResult) Interesting() bool {
	return r.Verdict == VerdictBypassed || r.Verdict == VerdictCheck
}

// bodySimilar is a cheap "are these basically the same response" test based on
// length ratio. Exact byte-compare is too strict (CSRF tokens, timestamps),
// full diffing is overkill here — within 10% length is a strong same-content
// signal for the BYPASSED verdict.
func bodySimilar(a, b int) bool {
	if a == 0 && b == 0 {
		return true
	}
	hi, lo := a, b
	if lo > hi {
		hi, lo = lo, hi
	}
	if hi == 0 {
		return false
	}
	return (hi-lo)*100/hi <= 10
}

func classifyAuth(baseline *store.Entry, statusAfter int, bodyAfter string) (AuthVerdict, string) {
	switch {
	case statusAfter == 401 || statusAfter == 403:
		return VerdictEnforced, fmt.Sprintf("replay rejected with %d", statusAfter)
	case statusAfter >= 200 && statusAfter < 300:
		if baseline.Status >= 200 && baseline.Status < 300 && bodySimilar(len(baseline.ResponseBody), len(bodyAfter)) {
			return VerdictBypassed, fmt.Sprintf("replay got %d with a body within 10%% of the original — the swapped identity sees the same data", statusAfter)
		}
		return VerdictCheck, fmt.Sprintf("replay got %d but the body differs from baseline (%d vs %d bytes) — inspect manually", statusAfter, len(baseline.ResponseBody), len(bodyAfter))
	default:
		return VerdictUnknown, fmt.Sprintf("baseline %d -> replay %d", baseline.Status, statusAfter)
	}
}

// Identity describes who to replay as. The three knobs cover every way an app
// carries identity:
//
//	Headers — full replace/add of any header (Authorization, X-Api-Key, or a
//	          whole Cookie string). Overwrites case-insensitively.
//	Cookies — SURGICAL cookie edits: replace/add just these cookies inside the
//	          existing Cookie header and keep the rest (csrftoken, locale, …).
//	          This is what you want when the session is one cookie among many —
//	          a full Cookie replace would strip the CSRF token and the server
//	          would 403 for the wrong reason, faking an ENFORCED verdict.
//	Drop    — remove these headers entirely (e.g. drop Authorization to test
//	          the endpoint as a completely unauthenticated user).
//
// Order applied per request: clone original headers → Drop → Headers → Cookies.
type Identity struct {
	Headers map[string]string
	Cookies map[string]string
	Drop    []string
}

func (id Identity) apply(e *store.Entry) map[string]string {
	h := make(map[string]string, len(e.RequestHeaders)+len(id.Headers)+1)
	for k, v := range e.RequestHeaders {
		h[k] = v
	}
	for _, name := range id.Drop {
		for k := range h {
			if strings.EqualFold(k, name) {
				delete(h, k)
			}
		}
	}
	for k, v := range id.Headers {
		for ek := range h { // drop any differently-cased duplicate first
			if strings.EqualFold(ek, k) {
				delete(h, ek)
			}
		}
		h[k] = v
	}
	if len(id.Cookies) > 0 {
		h[cookieKey(h)] = editCookies(currentCookie(h), id.Cookies)
	}
	return h
}

func currentCookie(h map[string]string) string {
	for k, v := range h {
		if strings.EqualFold(k, "cookie") {
			return v
		}
	}
	return ""
}

func cookieKey(h map[string]string) string {
	for k := range h {
		if strings.EqualFold(k, "cookie") {
			return k
		}
	}
	return "Cookie"
}

// editCookies replaces/adds the named cookies inside an existing Cookie header,
// preserving every other cookie and the original order.
func editCookies(current string, edits map[string]string) string {
	type kv struct{ k, v string }
	var pairs []kv
	at := map[string]int{}
	for _, part := range strings.Split(current, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val := part, ""
		if i := strings.Index(part, "="); i >= 0 {
			name, val = part[:i], part[i+1:]
		}
		at[name] = len(pairs)
		pairs = append(pairs, kv{name, val})
	}
	for name, val := range edits {
		if idx, ok := at[name]; ok {
			pairs[idx].v = val
		} else {
			at[name] = len(pairs)
			pairs = append(pairs, kv{name, val})
		}
	}
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "; ")
}

// Authorize replays every entry once as the given Identity and returns a
// verdict per entry.
func Authorize(entries []*store.Entry, id Identity, concurrency int) []AuthResult {
	raw := runBatchAuth(entries, concurrency, func(e *store.Entry) AuthResult {
		h := id.apply(e)
		status, body, ms, err := fire(e.Method, e.URL, h, e.RequestBody)
		res := AuthResult{
			EntryID: e.ID, Method: e.Method, URL: e.URL,
			StatusBefore: e.Status, StatusAfter: status,
			LenBefore: len(e.ResponseBody), LenAfter: len(body),
			DurationMs: ms,
		}
		if err != nil {
			res.Verdict, res.Note, res.Error = VerdictUnknown, "request error", err.Error()
			return res
		}
		res.Verdict, res.Note = classifyAuth(e, status, body)
		return res
	})
	return raw
}

func runBatchAuth(entries []*store.Entry, concurrency int, work func(*store.Entry) AuthResult) []AuthResult {
	if concurrency < 1 {
		concurrency = 10
	}
	sem := make(chan struct{}, concurrency)
	out := make([]AuthResult, len(entries))
	done := make(chan int, len(entries))
	for i, e := range entries {
		sem <- struct{}{}
		go func(i int, e *store.Entry) {
			defer func() { <-sem }()
			out[i] = work(e)
			done <- i
		}(i, e)
	}
	for range entries {
		<-done
	}
	return out
}

// ParseHeaderList turns repeated "Name: Value" strings into a map.
func ParseHeaderList(pairs []string) (map[string]string, error) {
	h := map[string]string{}
	for _, p := range pairs {
		idx := strings.Index(p, ":")
		if idx < 0 {
			return nil, fmt.Errorf(`bad header %q — want "Name: Value"`, p)
		}
		name := strings.TrimSpace(p[:idx])
		val := strings.TrimSpace(p[idx+1:])
		if name == "" {
			return nil, fmt.Errorf(`bad header %q — empty name`, p)
		}
		h[name] = val
	}
	return h, nil
}

// ParseCookieList turns repeated "name=value" strings into a map for surgical
// cookie swaps.
func ParseCookieList(pairs []string) (map[string]string, error) {
	c := map[string]string{}
	for _, p := range pairs {
		i := strings.Index(p, "=")
		if i <= 0 {
			return nil, fmt.Errorf(`bad cookie %q — want name=value`, p)
		}
		c[strings.TrimSpace(p[:i])] = strings.TrimSpace(p[i+1:])
	}
	return c, nil
}
