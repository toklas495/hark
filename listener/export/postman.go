package export

import (
	"encoding/json"
	"fmt"
	"net/url"

	"hark/store"
)

type postmanHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type postmanBody struct {
	Mode string `json:"mode"`
	Raw  string `json:"raw"`
}

type postmanRequest struct {
	Method string          `json:"method"`
	Header []postmanHeader `json:"header"`
	URL    struct {
		Raw string `json:"raw"`
	} `json:"url"`
	Body *postmanBody `json:"body,omitempty"`
}

type postmanResponse struct {
	Name   string          `json:"name"`
	Status string          `json:"status"`
	Code   int             `json:"code"`
	Header []postmanHeader `json:"header"`
	Body   string          `json:"body"`
}

type postmanItem struct {
	Name     string            `json:"name"`
	Request  postmanRequest    `json:"request"`
	Response []postmanResponse `json:"response,omitempty"`
}

type postmanCollection struct {
	Info struct {
		Name   string `json:"name"`
		Schema string `json:"schema"`
	} `json:"info"`
	Item []postmanItem `json:"item"`
}

func headersToPostman(h map[string]string) []postmanHeader {
	out := make([]postmanHeader, 0, len(h))
	for k, v := range h {
		out = append(out, postmanHeader{Key: k, Value: v})
	}
	return out
}

func ToPostman(entries []*store.Entry) ([]byte, error) {
	var col postmanCollection
	col.Info.Name = "API Capture"
	col.Info.Schema = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"

	for _, e := range entries {
		path := e.URL
		if u, err := url.Parse(e.URL); err == nil {
			path = u.Path
		}
		item := postmanItem{
			Name: fmt.Sprintf("%s %s", e.Method, path),
			Request: postmanRequest{
				Method: e.Method,
				Header: headersToPostman(e.RequestHeaders),
			},
		}
		item.Request.URL.Raw = e.URL
		if e.RequestBody != "" {
			item.Request.Body = &postmanBody{Mode: "raw", Raw: e.RequestBody}
		}
		if e.Status != 0 {
			item.Response = []postmanResponse{{
				Name:   fmt.Sprintf("Response (%d)", e.Status),
				Status: e.StatusText,
				Code:   e.Status,
				Header: headersToPostman(e.ResponseHeaders),
				Body:   e.ResponseBody,
			}}
		}
		col.Item = append(col.Item, item)
	}
	return json.MarshalIndent(col, "", "  ")
}
