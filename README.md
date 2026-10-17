# hark

> Watch, don't sit in the middle.

`hark` captures your browser's API traffic **passively** — no proxy, no CA
cert, nothing for a corporate proxy or EDR to choke on — and turns it into
plain NDJSON you pipe straight into your other tools.

It is two pieces plus a handful of filters:

```
  browser ──(Chrome debugger / CDP)──► [extension] ──POST──► [hark listen] ──► captures.ndjson
                                                                                    │
   the filters below just read that file (or stdin) and write one clean format:     ▼
     hark entries                 what did we catch
     hark req -id <id>            one raw HTTP request   → sqlmap -r / nosqlmap / ffuf -request
     hark urls                    deduped URL list       → nuclei -l / httpx
     hark words                   wordlist               → ffuf -w
     hark auth -as '<identity>'   autorize, no Burp      → BFLA / broken-access-control
     hark export -format ...      postman | har | nuclei | curl | ndjson
```

Why passive: a proxy sits in the path of every request and can be blocked,
throttled, or detected. `hark` only *reads* the traffic the browser already
makes, so it works in locked-down UAT/VPN environments where Burp dies.

## Build

```sh
cd listener
go build -o hark .
```

Single static binary, no dependencies.

## Quick start

1. **Run the listener** (the only long-running piece):

   ```sh
   hark listen
   ```

   It prints a one-time token. Copy it.

2. **Load the extension**: `chrome://extensions` → Developer mode → *Load
   unpacked* → select the `extension/` folder.

3. **In the popup**: paste the token, (optionally) add a scope host like
   `api.example.com`, flip **Capture enabled** on. The dot goes green when the
   listener is reachable.

4. **Browse the app.** Every in-scope request lands in `captures.ndjson`.

## The pipeline

```sh
# list what you captured
hark entries

# feed one request to sqlmap / nosqlmap
hark req -id 1792...-7 | sqlmap -r /dev/stdin --batch
hark req -id 1792...-7 -out req.txt && sqlmap -r req.txt

# directory/param fuzz with ffuf
hark req -id 1792...-7 -fuzz query:id -out req.txt
ffuf -request req.txt -w $(hark words -out wordlist.txt; echo wordlist.txt)

# recon feed (nuclei, httpx)
hark urls | nuclei -l -

# full authenticated feed for nuclei (keeps headers/cookies/body)
hark export -format nuclei > nuclei-input.jsonl && nuclei -im jsonl -l nuclei-input.jsonl
```

Everything reads `-data captures.ndjson` by default, or `-data -` to read
NDJSON from stdin — so filters compose with `jq`, `anew`, `grep`, `gf`:

```sh
cat captures.ndjson | jq 'select(.method=="POST")' | hark urls -data -
```

## autorize (broken access control, without Burp)

The captured response is the baseline (recorded as whoever you crawled as —
usually the privileged user). `hark auth` replays each request with a
different identity swapped in and tells you whether access control held:

Identity can live in a header, a cookie, or several places at once — mix any of
these (each repeatable):

```sh
# token in a header
hark auth -filter /admin -as 'Authorization: Bearer <seller-token>'
hark auth -as 'X-Api-Key: <seller-key>'

# identity in a cookie — use -cookie, NOT -as 'Cookie: ...' (see trap below)
hark auth -cookie 'session=<seller-session>'

# several at once
hark auth -as 'Authorization: Bearer <low>' -cookie 'tenant=2'

# test the endpoint as a completely unauthenticated user
hark auth -drop Authorization -drop Cookie
```

| flag | what it does |
|------|--------------|
| `-as "Name: Value"` | replace/add a whole header (Authorization, X-Api-Key, or an entire Cookie string) |
| `-cookie name=value` | surgically replace/add **one** cookie and keep the rest |
| `-drop Name` | remove a header entirely |

### The Cookie trap

A session is usually one cookie among many:
`Cookie: session=ADMIN; csrftoken=abc; locale=en`. If you swap the whole header
with `-as 'Cookie: session=SELLER'`, you also delete `csrftoken` — the server
then returns **403 for a missing CSRF token**, and `hark` reports `ENFORCED`
even though access control was never actually tested. That's a false negative
that hides the bug.

Use `-cookie session=SELLER` instead: it edits just that cookie inside the
captured Cookie header and leaves `csrftoken` and everything else intact, so the
only thing that changed between baseline and replay is the identity — which is
the whole point of the test.

Verdicts, strongest first:

| verdict    | meaning |
|------------|---------|
| `BYPASSED` | replay got the same 2xx with a near-identical body — the low-priv identity sees privileged data. **The bug.** |
| `CHECK`    | 2xx but the body differs — could be per-user data, could be a partial leak. Look. |
| `ENFORCED` | replay got 401/403 — access control works. |
| `UNKNOWN`  | network error / 404 / 5xx — reported as-is. |

A table goes to stderr; JSONL (flagged rows, or `-all`) goes to stdout.

`hark probe` is the lower-level engine underneath it (also does XSS/SSTI/SQLi
reflection fuzzing via `-swap-param`).

## Storage

NDJSON is the canonical format on purpose: append-only (a crash can't corrupt
earlier lines), line-oriented (greppable, `jq`/`anew`-friendly), streamable.

To keep it small, `hark listen` defaults to `-bodies api`: it keeps full
request/response for API calls but **drops the response body of static assets**
(JS/CSS/images/fonts) — their URL/headers/status are still logged, so recon and
wordlists are unaffected. `-bodies all` keeps everything; `-max-body` caps any
single body (default 2 MB).

## Security notes

- The listener binds `127.0.0.1` and gates `POST /capture` with a token, so a
  random site you browse can't forge captures into your log.
- There is **no GET that returns captures** — the daemon can't be used to
  exfiltrate your log over HTTP. Read the file directly.
- **`captures.ndjson` contains live auth tokens and cookies.** It's written
  `0600` and is git-ignored. Never commit it. Never paste it into a public
  repo or issue.
