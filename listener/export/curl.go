package export

import (
	"regexp"
	"strings"

	"hark/store"
)

var skipHeader = regexp.MustCompile(`(?i)^(content-length|host)$`)

func ToCurl(entries []*store.Entry) string {
	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("curl -X " + e.Method + " '" + e.URL + "'")
		for k, v := range e.RequestHeaders {
			if skipHeader.MatchString(k) {
				continue
			}
			b.WriteString(" \\\n  -H '" + k + ": " + strings.ReplaceAll(v, "'", `'\''`) + "'")
		}
		if e.RequestBody != "" {
			b.WriteString(" \\\n  -d '" + strings.ReplaceAll(e.RequestBody, "'", `'\''`) + "'")
		}
	}
	return b.String()
}
