// Package analyze turns captured traffic into inputs other CLI tools can
// consume directly — wordlists for ffuf, raw request files for ffuf's
// -request flag, plain URL lists for httpx/nuclei.
package analyze

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"hark/store"
)

// Skip headers that are boilerplate on every request — not useful as a
// fuzzing target, they'd just drown out the interesting custom ones
// (X-Api-Key, X-Auth-Token, X-Internal-*, etc).
var skipHeaders = map[string]bool{
	"host": true, "user-agent": true, "accept": true, "accept-language": true,
	"accept-encoding": true, "connection": true, "referer": true, "origin": true,
	"cookie": true, "content-length": true, "content-type": true, "sec-fetch-site": true,
	"sec-fetch-mode": true, "sec-fetch-dest": true, "sec-ch-ua": true, "sec-ch-ua-mobile": true,
	"sec-ch-ua-platform": true, "cache-control": true, "pragma": true, "priority": true,
}

var (
	numericSegment = regexp.MustCompile(`^[0-9]+$`)
	uuidSegment    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	longTokenLike  = regexp.MustCompile(`^[A-Za-z0-9_-]{24,}$`) // likely a session/opaque token, not a real path word
)

// isDynamic filters out path segments that are IDs/tokens rather than
// meaningful route words — a wordlist full of "8f3a9c1e..." isn't useful.
func isDynamic(segment string) bool {
	return numericSegment.MatchString(segment) || uuidSegment.MatchString(segment) || longTokenLike.MatchString(segment)
}

type Wordlist struct {
	Paths    []string
	Params   []string
	Headers  []string
	JSONKeys []string
}

func Generate(entries []*store.Entry) Wordlist {
	paths := map[string]bool{}
	params := map[string]bool{}
	headers := map[string]bool{}
	jsonKeys := map[string]bool{}

	for _, e := range entries {
		u, err := url.Parse(e.URL)
		if err == nil {
			for _, seg := range strings.Split(u.Path, "/") {
				if seg == "" || isDynamic(seg) {
					continue
				}
				paths[seg] = true
			}
			for k := range u.Query() {
				params[k] = true
			}
		}

		for k := range e.RequestHeaders {
			lk := strings.ToLower(k)
			if !skipHeaders[lk] {
				headers[k] = true
			}
		}

		collectJSONKeys(e.RequestBody, jsonKeys)
		collectJSONKeys(e.ResponseBody, jsonKeys)
	}

	return Wordlist{
		Paths:    sortedKeys(paths),
		Params:   sortedKeys(params),
		Headers:  sortedKeys(headers),
		JSONKeys: sortedKeys(jsonKeys),
	}
}

// collectJSONKeys walks a JSON body (if it is one) and records every key,
// one level flattened with dot notation for nested objects.
func collectJSONKeys(body string, out map[string]bool) {
	if body == "" {
		return
	}
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return // not JSON — nothing to extract
	}
	walkJSON("", v, out, 0)
}

func walkJSON(prefix string, v any, out map[string]bool, depth int) {
	if depth > 4 {
		return // don't recurse forever on deeply nested payloads
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			out[k] = true // bare key, most useful for a wordlist
			walkJSON(full, val, out, depth+1)
		}
	case []any:
		for _, item := range t {
			walkJSON(prefix, item, out, depth+1)
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Combined returns every category merged into one deduped, sorted list —
// what most fuzzing tools want as a single -w wordlist file.
func (w Wordlist) Combined() []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{w.Paths, w.Params, w.Headers, w.JSONKeys} {
		for _, item := range list {
			if !seen[item] {
				seen[item] = true
				out = append(out, item)
			}
		}
	}
	sort.Strings(out)
	return out
}
