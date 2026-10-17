# ⚠️ Do this first: purge the leaked capture log

The public `api-capture` repo currently commits `listener-go/captures.ndjson`,
which contains **real traffic from a live engagement** — valid-looking JWT
`access_token`s, `Cookie` headers, and the internal API map of
`onefinuat.auxilo.com`. Deleting the file in a new commit is **not enough**;
it stays in the git history and anyone can check it out.

## 1. Rotate / assume-burned

Treat every token and cookie in that file as compromised. They're likely
expired already, but tell the client so they can rotate anything long-lived.

## 2. Remove it from history

Using `git filter-repo` (recommended — install via `pip install git-filter-repo`):

```sh
# from a FRESH clone of the repo
git clone https://github.com/toklas495/api-capture
cd api-capture

git filter-repo --invert-paths \
  --path listener-go/captures.ndjson \
  --path-glob 'listener-go/dist/*'

# re-add the remote (filter-repo drops it) and force-push the rewritten history
git remote add origin https://github.com/toklas495/api-capture
git push origin --force --all
git push origin --force --tags
```

If you can't install `git-filter-repo`, the simplest safe alternative is to
**delete the repo on GitHub and re-create it** from the cleaned tree in this
package (which has no capture log and no binaries).

## 3. Keep it from happening again

The included `.gitignore` already excludes `*.ndjson`, `captures*`, `dist/`,
and build outputs. Verify before every push:

```sh
git status --ignored     # captures.ndjson should show under "Ignored files"
git ls-files | grep -i ndjson   # must print nothing
```

## 4. Don't commit the binaries either

The four ~8 MB files under `listener-go/dist/` bloat the repo. Build them in
CI and attach to a GitHub Release instead:

```sh
GOOS=linux   GOARCH=amd64 go build -o dist/hark-linux-amd64 ./listener
GOOS=darwin  GOARCH=arm64 go build -o dist/hark-macos-arm64 ./listener
GOOS=windows GOARCH=amd64 go build -o dist/hark-windows-amd64.exe ./listener
```
