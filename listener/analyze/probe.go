// probe.go is the one generic engine behind IDOR/BFLA/SSTI/XSS/SQLi
// testing: substitute one thing (a header or a param value), fire the
// modified request, and diff the response against the baseline that was
// ALREADY captured — no need to re-fire the original. Three signals are
// checked, strongest wins:
//
//  1. reflected/evaluated payload in the response body — near-proof,
//     and distinguishes literal reflection (XSS) from evaluated output
//     (SSTI: the payload string itself is gone, but "49" from {{7*7}}
//     shows up instead)
//  2. status code flip from baseline — strong signal for BFLA/IDOR
//  3. response length/body delta from baseline — weakest, most false
//     positives (pagination, timestamps, etc. also shift length)
package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"hark/store"
)

// Known expression-language markers and what they evaluate to. If the
// literal payload string is gone from the response but "49" shows up
// instead, the server evaluated it server-side — that's SSTI, not XSS,
// and it's a meaningfully different (and higher-severity) finding.
var exprEvalPayloads = map[string]string{
	"{{7*7}}":    "49",
	"${7*7}":     "49",
	"#{7*7}":     "49",
	"<%= 7*7 %>": "49",
	"@(7*7)":     "49",
	"{{7*'7'}}":  "7777777", // Jinja2-specific quirk: string repetition, not multiplication
}

var DefaultPayloads = []string{
	`<script>alert(1)</script>`,
	`"><svg onload=alert(1)>`,
	`{{7*7}}`,
	`${7*7}`,
	`' OR '1'='1`,
	`';--`,
}

type ProbeResult struct {
	EntryID      string `json:"entryId"`
	URL          string `json:"url"`
	Payload      string `json:"payload,omitempty"`
	SwapField    string `json:"swapField"`
	StatusBefore int    `json:"statusBefore"`
	StatusAfter  int    `json:"statusAfter"`
	LenBefore    int    `json:"lenBefore"`
	LenAfter     int    `json:"lenAfter"`
	Signal       string `json:"signal"` // "reflected" | "status_change" | "length_delta" | "none"
	Confidence   string `json:"confidence,omitempty"`
	Note         string `json:"note,omitempty"`
	DurationMs   int64  `json:"durationMs"`
	Error        string `json:"error,omitempty"`
}

func (r ProbeResult) Interesting() bool { return r.Signal != "none" && r.Signal != "" }

// SwapHeader clones the entry's headers with one header replaced/added.
func SwapHeader(e *store.Entry, name, value string) map[string]string {
	h := make(map[string]string, len(e.RequestHeaders)+1)
	for k, v := range e.RequestHeaders {
		h[k] = v
	}
	h[name] = value
	return h
}

// SwapParam replaces a query param or top-level JSON body key's value.
// Returns ok=false if the entry doesn't actually contain that param —
// callers should skip rather than fire a meaningless request.
func SwapParam(e *store.Entry, param, value string) (newURL string, newBody string, ok bool) {
	u, err := url.Parse(e.URL)
	if err == nil {
		q := u.Query()
		if _, exists := q[param]; exists {
			q.Set(param, value)
			u.RawQuery = q.Encode()
			return u.String(), e.RequestBody, true
		}
	}
	if e.RequestBody != "" {
		var obj map[string]any
		if err := json.Unmarshal([]byte(e.RequestBody), &obj); err == nil {
			if _, exists := obj[param]; exists {
				obj[param] = value
				b, _ := json.Marshal(obj)
				return e.URL, string(b), true
			}
		}
	}
	return "", "", false
}

var probeClient = &http.Client{Timeout: 15 * time.Second}

func fire(method, rawURL string, headers map[string]string, body string) (status int, respBody string, durationMs int64, err error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return 0, "", 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := probeClient.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return 0, "", elapsed, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, string(raw), elapsed, nil
}

// checkReflection distinguishes three cases: the payload came back
// unescaped verbatim (XSS candidate), an expression payload's EVALUATED
// result came back instead of the literal string (SSTI candidate), or
// neither.
func checkReflection(payload, body string) (matched bool, note string) {
	if payload == "" {
		return false, ""
	}
	if strings.Contains(body, payload) {
		return true, "payload reflected unescaped — possible XSS"
	}
	if evald, ok := exprEvalPayloads[payload]; ok && strings.Contains(body, evald) {
		return true, fmt.Sprintf("payload not present, but evaluated result %q is — possible SSTI", evald)
	}
	return false, ""
}

// Diff scores a fired variant against the baseline that was captured
// originally, picking the single strongest signal.
func Diff(baseline *store.Entry, payload string, statusAfter int, bodyAfter string, durationMs int64) ProbeResult {
	r := ProbeResult{
		StatusBefore: baseline.Status, StatusAfter: statusAfter,
		LenBefore: len(baseline.ResponseBody), LenAfter: len(bodyAfter),
		DurationMs: durationMs, Payload: payload,
	}

	if reflected, note := checkReflection(payload, bodyAfter); reflected {
		r.Signal = "reflected"
		r.Confidence = "high"
		r.Note = note
		return r
	}

	if baseline.Status != 0 && statusAfter != 0 && baseline.Status != statusAfter {
		r.Signal = "status_change"
		// a locked-down status opening up is the interesting direction;
		// tightening (200 -> 403) is expected/boring noise most of the time
		if isLocked(baseline.Status) && !isLocked(statusAfter) {
			r.Confidence = "high"
			r.Note = fmt.Sprintf("status %d -> %d: previously-blocked request now succeeded", baseline.Status, statusAfter)
		} else {
			r.Confidence = "low"
			r.Note = fmt.Sprintf("status %d -> %d", baseline.Status, statusAfter)
		}
		return r
	}

	if r.LenBefore > 0 {
		delta := abs(r.LenAfter-r.LenBefore) * 100 / r.LenBefore
		if delta >= 15 {
			r.Signal = "length_delta"
			r.Confidence = "medium"
			r.Note = fmt.Sprintf("response length changed %d%% (%d -> %d bytes)", delta, r.LenBefore, r.LenAfter)
			return r
		}
	}

	r.Signal = "none"
	return r
}

func isLocked(status int) bool { return status == 401 || status == 403 }
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// RunHeaderSwap fires every entry once with one header replaced — the
// BFLA/auth-bypass mode: same request, different identity.
func RunHeaderSwap(entries []*store.Entry, headerName, headerValue string, concurrency int) []ProbeResult {
	return runBatch(entries, concurrency, func(e *store.Entry) []ProbeResult {
		headers := SwapHeader(e, headerName, headerValue)
		status, body, ms, err := fire(e.Method, e.URL, headers, e.RequestBody)
		res := Diff(e, "", status, body, ms)
		res.EntryID, res.URL, res.SwapField = e.ID, e.URL, "header:"+headerName
		if err != nil {
			res.Error = err.Error()
		}
		return []ProbeResult{res}
	})
}

// RunParamFuzz fires one request per payload, per entry that actually
// contains the target param — the injection-testing mode (XSS/SSTI/SQLi).
func RunParamFuzz(entries []*store.Entry, param string, payloads []string, concurrency int) []ProbeResult {
	return runBatch(entries, concurrency, func(e *store.Entry) []ProbeResult {
		var out []ProbeResult
		if _, _, ok := SwapParam(e, param, "x"); !ok {
			return nil // this entry doesn't have the param — don't waste payloads on it
		}
		for _, p := range payloads {
			u, b, _ := SwapParam(e, param, p)
			status, respBody, ms, err := fire(e.Method, u, e.RequestHeaders, b)
			res := Diff(e, p, status, respBody, ms)
			res.EntryID, res.URL, res.SwapField = e.ID, e.URL, "param:"+param
			if err != nil {
				res.Error = err.Error()
			}
			out = append(out, res)
		}
		return out
	})
}

func runBatch(entries []*store.Entry, concurrency int, work func(*store.Entry) []ProbeResult) []ProbeResult {
	if concurrency < 1 {
		concurrency = 10
	}
	sem := make(chan struct{}, concurrency)
	resultsCh := make(chan []ProbeResult, len(entries))
	var wg sync.WaitGroup

	for _, e := range entries {
		wg.Add(1)
		sem <- struct{}{}
		go func(entry *store.Entry) {
			defer wg.Done()
			defer func() { <-sem }()
			resultsCh <- work(entry)
		}(e)
	}
	wg.Wait()
	close(resultsCh)

	var all []ProbeResult
	for rs := range resultsCh {
		all = append(all, rs...)
	}
	return all
}
