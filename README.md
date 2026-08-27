# shared-gated-sites

Static pages that are published to a public URL but whose contents are
encrypted, so the URL alone discloses nothing.

Each page lives in its own directory and holds a single `index.html`. The
readable content is AES-256-GCM ciphertext embedded in that file. The key is
derived from a passphrase with PBKDF2-HMAC-SHA256 over 600,000 iterations,
and decryption happens in the visitor's browser. No passphrase, no plaintext,
and no server involved.

The passphrase is never committed to this repository. It is generated at build
time, passed to the build script as an argument, and delivered to the reader
out of band.

Every page carries `noindex, nofollow`, and `robots.txt` disallows the whole
origin.

## Rebuilding a page

The build inputs are kept outside this repository. To regenerate one:

```
python3 build.py "<passphrase>"
```

which encrypts `payload.json` into `template.html` and writes `index.html`.

## Contents

| Path | What it is |
|---|---|
| `figure-signoff/` | A thirteen-question data request form |
