// hark — passively capture browser traffic, then pipe it into your tools.
//
// Philosophy: the browser already sees every request. hark watches (via the
// extension + CDP), the listener just appends it to an NDJSON log, and every
// other job is a small filter that reads that log and writes one clean format
// to stdout. Compose them with pipes, jq, anew, grep — like any unix tool.
//
//	hark listen                      # the only long-running piece
//	hark entries                     # what did we catch?
//	hark req  -id <id>  | sqlmap -r  # one request, raw, for sqlmap/nosqlmap
//	hark urls | nuclei -l -          # URL/host list for nuclei / Nessus targets
//	hark words > wl.txt              # wordlist for ffuf -w
//	hark auth -as 'Authorization: Bearer <low-priv>'   # autorize, no Burp
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"hark/analyze"
	"hark/export"
	"hark/server"
	"hark/store"
)

func main() {
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
		printHelp()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "listen":
		runListen(args)
	case "entries":
		runEntries(args)
	case "req":
		runReq(args)
	case "urls":
		runURLs(args)
	case "words", "wordlist":
		runWords(args)
	case "auth", "autorize":
		runAuth(args)
	case "probe":
		runProbe(args)
	case "export":
		runExport(args)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Print(`hark — watch browser traffic, pipe it into your tools

  hark listen [-addr 127.0.0.1:8787] [-data captures.ndjson]
              [-token TOKEN] [-bodies api|all] [-max-body 2097152]
      The headless listener. Receives captures from the extension and appends
      them to the NDJSON log. No dashboard, no repeater — on purpose.
      A token is generated and printed on first run; paste it into the
      extension. -bodies api (default) drops static-asset bodies to save space.

  Filters (read -data <file>, or "-data -" to read NDJSON from stdin):

  hark entries [-data captures.ndjson]
      List captured entries: id, method, status, url.

  hark req -id <id> [-fuzz <marker>] [-data captures.ndjson]
      Emit one captured request as a raw HTTP request on stdout.
      No -fuzz  -> plain raw request, ready for:  sqlmap -r  /  nosqlmap.
      -fuzz ""            append /FUZZ as a trailing path segment (ffuf -request)
      -fuzz path:N        replace path segment N (0-indexed)
      -fuzz query:name    replace that query param's value
      -fuzz header:name   replace that header's value
      -fuzz body          replace the whole body

  hark urls [-data captures.ndjson]
      Deduped URL list (recon; feeds nuclei -l, httpx, Nessus target import).

  hark words [-data captures.ndjson] [-out wordlist.txt] [-split]
      Path segments + param names + header names + JSON keys as a wordlist.

  hark auth [-as "Name: Value"] [-cookie name=value] [-drop Name]
            [-filter substr] [-data captures.ndjson] [-concurrency 10]
            [-all] [-out file.jsonl]
      Autorize: replay every captured request as another identity and report
      ENFORCED / BYPASSED / CHECK per endpoint by diffing against the
      originally-captured response. Table to stderr, JSONL to stdout.
      Identity (any mix, each repeatable):
        -as "Name: Value"   replace/add a whole header (Authorization, X-Api-Key,
                            or a full Cookie string)
        -cookie name=value  replace/add ONE cookie, keeping the others intact
                            (use this for session cookies — a full Cookie swap
                            would strip csrftoken and fake an ENFORCED verdict)
        -drop Name          remove a header entirely (e.g. -drop Authorization
                            to test the endpoint as unauthenticated)
      e.g.  hark auth -filter /admin -as 'Authorization: Bearer <seller-token>'
            hark auth -cookie session=<seller-session>
            hark auth -drop Authorization -drop Cookie      # as nobody

  hark probe (-swap-header "Name: Value" | -swap-param name [-payloads @file])
             [-filter substr] [-data captures.ndjson] [-concurrency 10] [-all]
      Lower-level fuzz engine behind auth/XSS/SSTI/SQLi: swap one thing, fire,
      diff vs baseline. JSONL on stdout.

  hark export -format ndjson|postman|har|nuclei|curl [-types api,static]
              [-data captures.ndjson]
      Convert the whole log to another format on stdout.
`)
}

// ---- shared loader -------------------------------------------------------

func load(dataFile string) []*store.Entry {
	if dataFile == "-" {
		return store.LoadStream(bufio.NewScanner(os.Stdin))
	}
	st, err := store.Open(dataFile)
	if err != nil {
		log.Fatalf("opening %s: %v", dataFile, err)
	}
	return st.List()
}

func filterURL(entries []*store.Entry, sub string) []*store.Entry {
	if sub == "" {
		return entries
	}
	var out []*store.Entry
	for _, e := range entries {
		if strings.Contains(e.URL, sub) {
			out = append(out, e)
		}
	}
	return out
}

func writeOut(path, content string) {
	if path == "" {
		fmt.Print(content)
		return
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		log.Fatalf("writing %s: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", path)
}

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ExitOnError)
}

func dataFlag(fs *flag.FlagSet) *string {
	return fs.String("data", "captures.ndjson", `capture log to read, or "-" for stdin`)
}

// ---- listen --------------------------------------------------------------

func runListen(args []string) {
	fs := newFlagSet("listen")
	addr := fs.String("addr", "127.0.0.1:8787", "listen address (keep it on localhost)")
	dataFile := fs.String("data", "captures.ndjson", "path to the NDJSON capture log")
	token := fs.String("token", "", "shared token the extension must send; generated if empty")
	bodies := fs.String("bodies", "api", `which response bodies to store: "api" (drop static) or "all"`)
	maxBody := fs.Int("max-body", 2<<20, "max stored body size in bytes (0 = unlimited)")
	fs.Parse(args)

	cfg := store.Config{MaxBodyBytes: *maxBody, StaticBodies: *bodies == "all"}
	st, err := store.New(*dataFile, cfg)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	tok := *token
	if tok == "" {
		tok = randToken()
	}
	srv := server.New(st, tok)

	fmt.Printf("hark listening:   http://%s/capture  (POST)\n", *addr)
	fmt.Printf("data file:        %s  (bodies=%s, max-body=%d)\n", *dataFile, *bodies, *maxBody)
	fmt.Printf("already stored:   %d entries\n", st.Count())
	fmt.Printf("\nextension token (paste into the popup):\n  %s\n\n", tok)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- entries -------------------------------------------------------------

func runEntries(args []string) {
	fs := newFlagSet("entries")
	dataFile := dataFlag(fs)
	fs.Parse(args)
	for _, e := range load(*dataFile) {
		fmt.Printf("%-28s  %-6s  %3d  %s\n", e.ID, e.Method, e.Status, e.URL)
	}
}

// ---- req -----------------------------------------------------------------

func runReq(args []string) {
	fs := newFlagSet("req")
	dataFile := dataFlag(fs)
	id := fs.String("id", "", "entry id (see: hark entries)")
	fuzz := fs.String("fuzz", "\x00", "insert FUZZ marker: path:N | query:name | header:name | body | \"\"")
	out := fs.String("out", "", "output file (default stdout)")
	fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "need -id (run: hark entries)")
		os.Exit(1)
	}
	var e *store.Entry
	for _, c := range load(*dataFile) {
		if c.ID == *id {
			e = c
			break
		}
	}
	if e == nil {
		fmt.Fprintf(os.Stderr, "no entry with id %s\n", *id)
		os.Exit(1)
	}

	var (
		raw string
		err error
	)
	if *fuzz == "\x00" { // flag not set -> plain raw request
		raw, err = analyze.PlainRawRequest(e)
	} else {
		raw, err = analyze.BuildFfufRequest(e, *fuzz)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeOut(*out, raw)
}

// ---- urls ----------------------------------------------------------------

func runURLs(args []string) {
	fs := newFlagSet("urls")
	dataFile := dataFlag(fs)
	out := fs.String("out", "", "output file (default stdout)")
	fs.Parse(args)

	seen := map[string]bool{}
	var b strings.Builder
	n := 0
	for _, e := range load(*dataFile) {
		if !seen[e.URL] {
			seen[e.URL] = true
			b.WriteString(e.URL)
			b.WriteByte('\n')
			n++
		}
	}
	writeOut(*out, b.String())
	fmt.Fprintf(os.Stderr, "%d unique URLs\n", n)
}

// ---- words ---------------------------------------------------------------

func runWords(args []string) {
	fs := newFlagSet("words")
	dataFile := dataFlag(fs)
	out := fs.String("out", "wordlist.txt", "output file (empty = stdout)")
	split := fs.Bool("split", false, "also write .paths/.params/.headers/.jsonkeys files")
	fs.Parse(args)

	wl := analyze.Generate(load(*dataFile))
	combined := wl.Combined()
	if len(combined) == 0 {
		fmt.Fprintln(os.Stderr, "no entries — nothing to extract")
		return
	}
	writeOut(*out, strings.Join(combined, "\n")+"\n")
	fmt.Fprintf(os.Stderr, "%d words (%d paths, %d params, %d headers, %d json keys)\n",
		len(combined), len(wl.Paths), len(wl.Params), len(wl.Headers), len(wl.JSONKeys))
	if *split && *out != "" {
		base := strings.TrimSuffix(*out, ".txt")
		writeOut(base+".paths.txt", strings.Join(wl.Paths, "\n")+"\n")
		writeOut(base+".params.txt", strings.Join(wl.Params, "\n")+"\n")
		writeOut(base+".headers.txt", strings.Join(wl.Headers, "\n")+"\n")
		writeOut(base+".jsonkeys.txt", strings.Join(wl.JSONKeys, "\n")+"\n")
	}
}

// ---- auth (autorize) -----------------------------------------------------

type repeatString []string

func (r *repeatString) String() string { return strings.Join(*r, ", ") }
func (r *repeatString) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func runAuth(args []string) {
	fs := newFlagSet("auth")
	dataFile := dataFlag(fs)
	var as, cookies, drop repeatString
	fs.Var(&as, "as", `replace/add a whole header, "Name: Value" (repeatable)`)
	fs.Var(&cookies, "cookie", `surgically replace/add ONE cookie, "name=value", keeping the rest (repeatable)`)
	fs.Var(&drop, "drop", `remove a header entirely, e.g. -drop Authorization (test as unauthenticated) (repeatable)`)
	filter := fs.String("filter", "", "only test entries whose URL contains this substring")
	concurrency := fs.Int("concurrency", 10, "parallel requests")
	all := fs.Bool("all", false, "print every verdict, not just BYPASSED/CHECK")
	out := fs.String("out", "", "write JSONL here instead of stdout")
	fs.Parse(args)

	if len(as) == 0 && len(cookies) == 0 && len(drop) == 0 {
		fmt.Fprintln(os.Stderr, `need at least one of -as / -cookie / -drop (the identity to replay as)`)
		os.Exit(1)
	}
	headers, err := analyze.ParseHeaderList(as)
	if err != nil {
		log.Fatal(err)
	}
	cookieEdits, err := analyze.ParseCookieList(cookies)
	if err != nil {
		log.Fatal(err)
	}
	identity := analyze.Identity{Headers: headers, Cookies: cookieEdits, Drop: drop}

	entries := filterURL(load(*dataFile), *filter)
	// only replay real API calls — replaying every static asset is noise
	var apis []*store.Entry
	for _, e := range entries {
		if e.Category != "static" {
			apis = append(apis, e)
		}
	}
	if len(apis) == 0 {
		fmt.Fprintln(os.Stderr, "no API entries match — nothing to test")
		return
	}
	fmt.Fprintf(os.Stderr, "replaying %d requests with swapped identity...\n\n", len(apis))

	results := analyze.Authorize(apis, identity, *concurrency)

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	var bypass, check int
	for _, r := range results {
		switch r.Verdict {
		case analyze.VerdictBypassed:
			bypass++
		case analyze.VerdictCheck:
			check++
		}
		fmt.Fprintf(os.Stderr, "  %-9s %-6s %3d->%-3d  %s\n", r.Verdict, r.Method, r.StatusBefore, r.StatusAfter, r.URL)
		if *all || r.Interesting() {
			enc.Encode(r)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d BYPASSED, %d CHECK, %d total\n", bypass, check, len(results))
}

// ---- probe (lower level) -------------------------------------------------

func runProbe(args []string) {
	fs := newFlagSet("probe")
	dataFile := dataFlag(fs)
	filter := fs.String("filter", "", "only probe entries whose URL contains this substring")
	swapHeader := fs.String("swap-header", "", `"Name: Value" — BFLA/auth-bypass mode`)
	swapParam := fs.String("swap-param", "", "param name to fuzz — injection mode")
	payloadsArg := fs.String("payloads", "", "comma list, or @file.txt. Omit for built-in defaults")
	concurrency := fs.Int("concurrency", 10, "parallel requests")
	all := fs.Bool("all", false, "print every result, not just flagged ones")
	out := fs.String("out", "", "output file (default stdout)")
	fs.Parse(args)

	if *swapHeader == "" && *swapParam == "" {
		fmt.Fprintln(os.Stderr, "need -swap-header or -swap-param")
		os.Exit(1)
	}
	entries := filterURL(load(*dataFile), *filter)
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no entries match — nothing to probe")
		return
	}
	fmt.Fprintf(os.Stderr, "probing %d entries...\n", len(entries))

	var results []analyze.ProbeResult
	if *swapHeader != "" {
		idx := strings.Index(*swapHeader, ":")
		if idx < 0 {
			log.Fatalf(`-swap-header must be "Name: Value"`)
		}
		name := strings.TrimSpace((*swapHeader)[:idx])
		val := strings.TrimSpace((*swapHeader)[idx+1:])
		results = analyze.RunHeaderSwap(entries, name, val, *concurrency)
	} else {
		payloads := analyze.DefaultPayloads
		if *payloadsArg != "" {
			if strings.HasPrefix(*payloadsArg, "@") {
				b, err := os.ReadFile(strings.TrimPrefix(*payloadsArg, "@"))
				if err != nil {
					log.Fatalf("reading payloads: %v", err)
				}
				payloads = strings.Split(strings.TrimSpace(string(b)), "\n")
			} else {
				payloads = strings.Split(*payloadsArg, ",")
			}
		}
		results = analyze.RunParamFuzz(entries, *swapParam, payloads, *concurrency)
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	shown := 0
	for _, r := range results {
		if !*all && !r.Interesting() {
			continue
		}
		enc.Encode(r)
		shown++
	}
	fmt.Fprintf(os.Stderr, "%d/%d shown\n", shown, len(results))
}

// ---- export --------------------------------------------------------------

func runExport(args []string) {
	fs := newFlagSet("export")
	dataFile := dataFlag(fs)
	format := fs.String("format", "ndjson", "ndjson|postman|har|nuclei|curl")
	types := fs.String("types", "", "comma list of categories to include (e.g. api,static); empty = all")
	fs.Parse(args)

	entries := load(*dataFile)
	if *types != "" {
		allowed := map[string]bool{}
		for _, t := range strings.Split(*types, ",") {
			allowed[strings.TrimSpace(t)] = true
		}
		var f []*store.Entry
		for _, e := range entries {
			if allowed[e.Category] {
				f = append(f, e)
			}
		}
		entries = f
	}

	var (
		out []byte
		err error
	)
	switch *format {
	case "postman":
		out, err = export.ToPostman(entries)
	case "har":
		out, err = export.ToHAR(entries)
	case "curl":
		out = []byte(export.ToCurl(entries))
	case "nuclei":
		out, err = export.ToProxifyJSONL(entries)
	case "ndjson":
		var b strings.Builder
		for _, e := range entries {
			line, _ := json.Marshal(e)
			b.Write(line)
			b.WriteByte('\n')
		}
		out = []byte(b.String())
	default:
		log.Fatalf("unknown format %q", *format)
	}
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(out)
}
