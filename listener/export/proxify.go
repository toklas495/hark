// Proxify-schema JSONL export. This exact envelope shape is what
// `nuclei -im jsonl` expects, and per ProjectDiscovery's own docs it's
// also compatible as input from/to Katana and Httpx. Unlike a bare URL
// list, this embeds the full raw request — headers, cookies, auth
// tokens, body — so authenticated flows survive the export intact.
package export

import (
	"bytes"
	"encoding/json"
	"time"

	"hark/analyze"
	"hark/store"
)

type proxifyHeader map[string]string

type proxifyRequest struct {
	Header proxifyHeader `json:"header"`
	Raw    string        `json:"raw"`
	Body   string        `json:"body,omitempty"`
}

type proxifyResponse struct {
	Header proxifyHeader `json:"header"`
	Body   string        `json:"body,omitempty"`
	Raw    string        `json:"raw"`
}

type proxifyLine struct {
	Timestamp string          `json:"timestamp"`
	URL       string          `json:"url"`
	Request   proxifyRequest  `json:"request"`
	Response  proxifyResponse `json:"response"`
}

func ToProxifyJSONL(entries []*store.Entry) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	for _, e := range entries {
		rawReq, err := analyze.PlainRawRequest(e)
		if err != nil {
			continue // skip entries with unparseable URLs rather than failing the whole export
		}
		reqHeader := proxifyHeader{}
		for k, v := range e.RequestHeaders {
			reqHeader[k] = v
		}
		reqHeader["method"] = e.Method

		respHeader := proxifyHeader{}
		for k, v := range e.ResponseHeaders {
			respHeader[k] = v
		}

		line := proxifyLine{
			Timestamp: time.UnixMilli(e.Timestamp).UTC().Format(time.RFC3339),
			URL:       e.URL,
			Request: proxifyRequest{
				Header: reqHeader,
				Raw:    rawReq,
				Body:   e.RequestBody,
			},
			Response: proxifyResponse{
				Header: respHeader,
				Body:   e.ResponseBody,
				Raw:    analyze.RenderRawResponse(e),
			},
		}
		if err := enc.Encode(line); err != nil {
			continue
		}
	}
	return buf.Bytes(), nil
}
