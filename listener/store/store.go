// Package store is the disk-backed capture log. Every entry is appended to
// an NDJSON file (one JSON object per line — cheap to append, no rewrite of
// history on every write, and the file stays valid even if the process is
// killed mid-run). The log is mirrored in memory for fast reads.
//
// Identical requests seen within a short window (same method+url+body) don't
// create duplicate rows — they bump a Count on the original instead. On real
// apps, polling/analytics endpoints fire the same call every few seconds and
// would otherwise flood the log.
package store

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	ID                   string            `json:"id"`
	TabID                int               `json:"tabId,omitempty"`
	URL                  string            `json:"url"`
	Method               string            `json:"method"`
	RequestHeaders       map[string]string `json:"requestHeaders,omitempty"`
	RequestBody          string            `json:"requestBody,omitempty"`
	ResourceType         string            `json:"resourceType,omitempty"`
	Status               int               `json:"status,omitempty"`
	StatusText           string            `json:"statusText,omitempty"`
	MimeType             string            `json:"mimeType,omitempty"`
	ResponseHeaders      map[string]string `json:"responseHeaders,omitempty"`
	ResponseBody         string            `json:"responseBody,omitempty"`
	ResponseBodyEncoding string            `json:"responseBodyEncoding,omitempty"`
	Timestamp            int64             `json:"timestamp"`
	Count                int               `json:"count"`            // how many times this exact request repeated
	Source               string            `json:"source,omitempty"` // "capture" | "replay"
	Category             string            `json:"category"`         // "api" | "static" | "other" — set on insert, drives filtering
}

// Config controls what the listener keeps on disk. The defaults implement
// the "drop static bodies + size cap" policy: keep the full request/response
// for API calls, but don't waste disk on the body of every JS/CSS/image.
type Config struct {
	// MaxBodyBytes caps the stored size of any single request/response body.
	// 0 means unlimited. Oversized bodies are truncated with a marker.
	MaxBodyBytes int
	// StaticBodies, when false, drops response bodies for static assets
	// (JS/CSS/images/fonts/media). Their headers/URL/status are still kept,
	// so recon and wordlists are unaffected — you just don't store the bytes.
	StaticBodies bool
}

func DefaultConfig() Config {
	return Config{MaxBodyBytes: 2 << 20, StaticBodies: false} // 2 MB cap, drop static bodies
}

// staticResourceType / staticExtensions classify a request as a static asset
// vs an actual API call. This runs once at insert time, not per-read, so
// filtering thousands of entries later is a cheap string compare.
var staticResourceTypes = map[string]bool{
	"Image": true, "Media": true, "Font": true, "Stylesheet": true,
	"Script": true, "Document": true, "TextTrack": true, "Manifest": true,
}

var staticExtensions = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".webp": true, ".avif": true, ".ico": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".pdf": true, ".mp4": true, ".webm": true, ".mp3": true, ".map": true,
}

func classify(resourceType, rawURL string) string {
	if staticResourceTypes[resourceType] {
		return "static"
	}
	if resourceType == "XHR" || resourceType == "Fetch" || resourceType == "Ping" {
		return "api"
	}
	if idx := strings.LastIndex(rawURL, "."); idx != -1 {
		ext := strings.ToLower(rawURL[idx:])
		if q := strings.IndexAny(ext, "?#"); q != -1 {
			ext = ext[:q]
		}
		if staticExtensions[ext] {
			return "static"
		}
	}
	return "api" // treat unknowns as API rather than silently dropping them
}

type Store struct {
	mu       sync.Mutex
	cfg      Config
	entries  []*Entry
	byID     map[string]*Entry
	seenHash map[string]string
	seenAt   map[string]time.Time
	filePath string
	file     *os.File
	writer   *bufio.Writer
	counter  int64
}

const dedupeWindow = 5 * time.Second

// New opens (or creates) the capture log for appending. Readers that only
// need to parse an existing file can pass Config{} — the config only affects
// what Add writes.
func New(path string, cfg Config) (*Store, error) {
	s := &Store{
		cfg:      cfg,
		byID:     make(map[string]*Entry),
		seenHash: make(map[string]string),
		seenAt:   make(map[string]time.Time),
		filePath: path,
	}
	if path == "" {
		return s, nil
	}
	if err := s.loadFromDisk(); err != nil {
		return nil, fmt.Errorf("loading existing capture log: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // 0600: the log holds live tokens
	if err != nil {
		return nil, fmt.Errorf("opening capture log for append: %w", err)
	}
	s.file = f
	s.writer = bufio.NewWriter(f)
	return s, nil
}

// Open is a read-only convenience for the filter subcommands.
func Open(path string) (*Store, error) { return New(path, Config{}) }

func (s *Store) loadFromDisk() error {
	f, err := os.Open(s.filePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 10<<20) // allow lines up to 10MB
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip a corrupted line rather than fail the whole load
		}
		ec := e
		if ec.Category == "" {
			ec.Category = classify(ec.ResourceType, ec.URL)
		}
		s.entries = append(s.entries, &ec)
		s.byID[ec.ID] = &ec
	}
	return scanner.Err()
}

func hashEntry(method, url, body string) string {
	h := sha1.Sum([]byte(method + ":" + url + ":" + body))
	return hex.EncodeToString(h[:])
}

func (s *Store) trim(e *Entry) {
	if !s.cfg.StaticBodies && e.Category == "static" {
		e.ResponseBody = ""
		e.ResponseBodyEncoding = ""
	}
	if s.cfg.MaxBodyBytes > 0 {
		if len(e.ResponseBody) > s.cfg.MaxBodyBytes && e.ResponseBodyEncoding != "base64" {
			e.ResponseBody = e.ResponseBody[:s.cfg.MaxBodyBytes] + "\n...[truncated by hark]"
		}
		if len(e.RequestBody) > s.cfg.MaxBodyBytes {
			e.RequestBody = e.RequestBody[:s.cfg.MaxBodyBytes] + "\n...[truncated by hark]"
		}
	}
}

// Add stores a new entry, or — if an identical request was just seen —
// bumps the existing entry's Count instead of creating a duplicate row.
func (s *Store) Add(e *Entry) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := hashEntry(e.Method, e.URL, e.RequestBody)
	if lastID, ok := s.seenHash[h]; ok {
		if t, ok2 := s.seenAt[h]; ok2 && time.Since(t) < dedupeWindow {
			if existing, ok3 := s.byID[lastID]; ok3 {
				existing.Count++
				s.seenAt[h] = time.Now()
				return existing
			}
		}
	}

	s.counter++
	if e.ID == "" {
		e.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), s.counter)
	}
	if e.Timestamp == 0 {
		e.Timestamp = time.Now().UnixMilli()
	}
	e.Count = 1
	e.Category = classify(e.ResourceType, e.URL)
	s.trim(e)

	s.entries = append(s.entries, e)
	s.byID[e.ID] = e
	s.seenHash[h] = e.ID
	s.seenAt[h] = time.Now()

	if s.writer != nil {
		b, _ := json.Marshal(e)
		s.writer.Write(b)
		s.writer.WriteByte('\n')
		s.writer.Flush() // flush per entry: a kill mid-run must not lose captures
	}
	return e
}

func (s *Store) List() []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

func (s *Store) Get(id string) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byID[id]
}

func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// LoadStream parses NDJSON entries from any reader (a file, or stdin for
// piping). Corrupted lines are skipped. Categories are backfilled.
func LoadStream(r *bufio.Scanner) []*Entry {
	r.Buffer(make([]byte, 1<<20), 10<<20)
	var out []*Entry
	for r.Scan() {
		line := r.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		ec := e
		if ec.Category == "" {
			ec.Category = classify(ec.ResourceType, ec.URL)
		}
		out = append(out, &ec)
	}
	return out
}
