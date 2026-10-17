package analyze

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"hark/store"
)

// BuildFfufRequest turns a captured entry into a raw HTTP request file,
// exactly the format ffuf's `-request` flag expects, with FUZZ inserted
// at the point you specify.
//
// markerSpec syntax:
//
//	""                  -> append /FUZZ as a new trailing path segment (directory fuzzing)
//	"path:N"             -> replace path segment N (0-indexed) with FUZZ
//	"query:paramName"    -> replace that query param's value with FUZZ
//	"header:HeaderName"  -> replace that header's value with FUZZ
//	"body"                -> replace the entire request body with FUZZ (for raw-value fuzzing)
func BuildFfufRequest(e *store.Entry, markerSpec string) (string, error) {
	u, err := url.Parse(e.URL)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}

	body := e.RequestBody
	headers := cloneHeaders(e.RequestHeaders)

	switch {
	case markerSpec == "":
		segs := strings.Split(strings.TrimSuffix(u.Path, "/"), "/")
		segs = append(segs, "FUZZ")
		u.Path = strings.Join(segs, "/")

	case strings.HasPrefix(markerSpec, "path:"):
		n, err := strconv.Atoi(strings.TrimPrefix(markerSpec, "path:"))
		if err != nil {
			return "", fmt.Errorf("invalid path index in %q", markerSpec)
		}
		segs := strings.Split(u.Path, "/")
		nonEmpty := 0
		found := false
		for i, s := range segs {
			if s == "" {
				continue
			}
			if nonEmpty == n {
				segs[i] = "FUZZ"
				found = true
				break
			}
			nonEmpty++
		}
		if !found {
			return "", fmt.Errorf("path segment %d not found in %s", n, u.Path)
		}
		u.Path = strings.Join(segs, "/")

	case strings.HasPrefix(markerSpec, "query:"):
		param := strings.TrimPrefix(markerSpec, "query:")
		q := u.Query()
		if _, ok := q[param]; !ok {
			return "", fmt.Errorf("query param %q not found", param)
		}
		q.Set(param, "FUZZ")
		u.RawQuery = q.Encode()

	case strings.HasPrefix(markerSpec, "header:"):
		name := strings.TrimPrefix(markerSpec, "header:")
		found := false
		for k := range headers {
			if strings.EqualFold(k, name) {
				headers[k] = "FUZZ"
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("header %q not found on this request", name)
		}

	case markerSpec == "body":
		body = "FUZZ"

	default:
		return "", fmt.Errorf("unrecognized marker spec %q — use path:N, query:name, header:name, or body", markerSpec)
	}

	return renderRawRequest(e.Method, u, headers, body), nil
}

// PlainRawRequest renders a captured entry as a raw HTTP request with no
// FUZZ marker — exactly what sqlmap's -r flag wants (it finds injectable
// parameters itself, or you mark one manually with *).
func PlainRawRequest(e *store.Entry) (string, error) {
	u, err := url.Parse(e.URL)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}
	return renderRawRequest(e.Method, u, e.RequestHeaders, e.RequestBody), nil
}

// RenderRawResponse renders a captured response as raw HTTP bytes — used
// alongside RenderRawRequest to fill the proxify JSONL envelope, which
// expects both request and response in raw wire format.
func RenderRawResponse(e *store.Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", e.Status, e.StatusText)
	for k, v := range e.ResponseHeaders {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	b.WriteString(e.ResponseBody)
	return b.String()
}

func cloneHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

func renderRawRequest(method string, u *url.URL, headers map[string]string, body string) string {
	var b strings.Builder

	path := u.Path
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)

	for k, v := range headers {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
			continue // ffuf/the client recalculates these
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}

	b.WriteString("\r\n")
	if body != "" {
		b.WriteString(body)
	}
	return b.String()
}
