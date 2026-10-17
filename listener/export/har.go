package export

import (
	"encoding/json"
	"time"

	"hark/store"
)

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	PostData    *struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
	} `json:"postData,omitempty"`
}

type harContent struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Content     harContent  `json:"content"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         struct {
		Send    int `json:"send"`
		Wait    int `json:"wait"`
		Receive int `json:"receive"`
	} `json:"timings"`
}

type harDoc struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

func headersToHAR(h map[string]string) []harHeader {
	out := make([]harHeader, 0, len(h))
	for k, v := range h {
		out = append(out, harHeader{Name: k, Value: v})
	}
	return out
}

func ToHAR(entries []*store.Entry) ([]byte, error) {
	var doc harDoc
	doc.Log.Version = "1.2"
	doc.Log.Creator.Name = "go-listener"
	doc.Log.Creator.Version = "1.0"

	for _, e := range entries {
		he := harEntry{
			StartedDateTime: time.UnixMilli(e.Timestamp).UTC().Format(time.RFC3339),
			Request: harRequest{
				Method:      e.Method,
				URL:         e.URL,
				HTTPVersion: "HTTP/1.1",
				Headers:     headersToHAR(e.RequestHeaders),
			},
			Response: harResponse{
				Status:      e.Status,
				StatusText:  e.StatusText,
				HTTPVersion: "HTTP/1.1",
				Headers:     headersToHAR(e.ResponseHeaders),
				Content:     harContent{MimeType: e.MimeType, Text: e.ResponseBody},
			},
		}
		if e.RequestBody != "" {
			he.Request.PostData = &struct {
				MimeType string `json:"mimeType"`
				Text     string `json:"text"`
			}{MimeType: "application/json", Text: e.RequestBody}
		}
		doc.Log.Entries = append(doc.Log.Entries, he)
	}
	return json.MarshalIndent(doc, "", "  ")
}
