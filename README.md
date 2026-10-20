# Header Analyzer

**Header Analyzer** analyses the security headers of a raw HTTP response and explains
what each one leaves open, entirely in your browser. There is no server and nothing
to install, and nothing you paste leaves the page.

It reads headers the way a browser reads them. Parsing follows RFC 9110/9112, RFC
9651 structured fields, the Fetch, HTML and Encoding standards and CSP Level 3. The
recommendations follow two primary sources, the
[OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
and the [OWASP Secure Headers Project best practices](https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md).
Every check, condition and severity is documented in [`RULES.md`](RULES.md).

---

## Use it

**Online.** [tools.frankheat.io/headers](https://tools.frankheat.io/headers/). The
page is static: what you paste is analysed in your browser and never sent anywhere.

**Single file.** Open `dist/header-analyzer.html` in any modern browser. It is
self-contained (≈290 KB) and works offline, and you can share it as an attachment.

**From the folder.** Open `index.html` directly (double-click). This needs no
build step and no server.

Then paste a raw response into the text field. A raw response is a status line followed by one
`Name: value` per line. One response is analysed, the first in the text. Any of
these work:

```bash
curl -si https://example.com
```

- The output of `curl -i`. A `100 Continue` printed before the response is skipped.
- A Burp *request and response* copy. The request is skipped.
- Headers copied from browser DevTools, with or without a status line.

## What you get

- **Three severities: HIGH, MEDIUM, LOW.** They are anchored on OWASP ZAP,
  arbitrated with OWASP ASVS 5.0 and Mozilla Observatory, on the OWASP Risk Rating
  scale. A check that passes is **OK**, sometimes with a note that explains the
  result. [`RULES.md`](RULES.md) gives the source for every grade, and marks
  every case where Header Analyzer grades differently from a source, with the reason.
- **Findings ready for a report.** The **Copy findings** button copies one line
  per header, in the form
  `<Header>: <Missing | Misconfigured | Duplicated | Deprecated>. <brief description>.`,
  as a bulleted list. Its menu chooses what to copy: **All** findings, only the
  **Confirmed** ones (settled by the response), or only those **To confirm**.
  Each header appears once per list.
- **A row for each header.** Its value, every finding, and either a recommendation
  or the check that settles it.
- **Sources for every claim.** Each finding lists the passages it rests on (OWASP,
  ASVS, ZAP, RFCs, W3C/WHATWG specifications, MDN). A link opens the source
  scrolled to the exact passage, highlighted; code is linked by line range on a
  pinned commit. [`RULES.md`](RULES.md) links every rule the same way.
- **Two fixed profiles.** *Basic* checks 17 headers: the core security headers,
  the deprecated X-XSS-Protection and Expect-CT, and the charset of an HTML
  Content-Type. *Extended* checks 25: it adds Clear-Site-Data (a check for
  logout responses), legacy headers, and asks about HSTS preload. Profiles cannot be edited, so every report is produced by the same rules.
- **Web page or REST API.** A second choice says what the response is; nothing
  is guessed from it. *Web page* applies the rules above. *REST API* judges the
  response as an API call read by a browser, on the
  [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html):
  with Basic only the headers that cheat sheet lists, with Extended the same 25
  headers, each with the criterion for an API response.
- **Accessible.** Keyboard navigation, screen-reader announcements, reduced motion,
  and a light/dark switch that follows the system until you choose a theme.
  Severity is always written as a word, never shown by
  colour alone.

### "To confirm"

Some verdicts depend on something a saved response cannot show. Does the page use
the camera? Is this endpoint's CORS origin reflected or allowlisted? Does this
response carry a signed-in user's data? Those findings carry the check that
settles them and what each outcome means. Their severity is what the response
shows; the worst case a check could reveal is stated in the check itself. They are
marked `?`.

One case where the response itself makes a finding uncertain:

- **HTML without a usable charset.** A `text/html` response with no `charset`, or
  one the browser does not recognise, is to confirm. The page can still declare
  the encoding with `<meta charset>`, which the headers do not show.

## Privacy and security of the tool itself

- **No network access.** Everything runs in the page. The page's own
  Content-Security-Policy forbids network connections (`default-src 'none'`).
  Source links open in a new tab only when you click them, and send no referrer.
- **No HTML injection.** Input reaches the page only as text (`textContent`). The
  test suite fails if the interface ever uses `innerHTML`, `eval` or a network API.
- **Nothing stored.** The input is never written to storage. Only the profile and
  theme choices are remembered.
- **Strict CSP in the single file.** `dist/header-analyzer.html` pins the exact SHA-256
  hash of its inline script and stylesheet, so nothing else can run in it.

## Development

Requirements: Node.js ≥ 20. No dependencies.

```bash
npm test
```

```bash
npm run build
```

```bash
npm run verify-sources
```

`npm test` runs ≈500 tests with `node:test`. They cover the parser, RFC 9651, every
checker, the CSP engine, duplicates and correlations, and the findings list. They also
include a 6,000-case fuzz run and static safety checks on the interface.
`npm run build` regenerates `dist/header-analyzer.html`. `npm run verify-sources` fetches every
cited document and checks that each quoted passage is still there, word for word (it
needs network access, so it is not part of `npm test`); `npm run sources` regenerates
the citation list at the end of `RULES.md`.

```
index.html             the page (loads the scripts below, in order)
assets/                styles.css, icon.svg
src/core/              the engine: runs unchanged in the browser and in Node
  models.js            severities, findings
  sources.js           every cited passage, with its highlighted link
  fields.js            list splitting, RFC 9651 structured-field parser
  parser.js            raw text → response → header fields
  csp.js               Content-Security-Policy (CSP Level 3)
  rules.js             every other header, duplicate resolution, orchestration
  correlations.js      checks that need more than one header
  profiles.js          the two fixed profiles and the two modes
  engine.js            analyze(), findingList()
src/ui/                app.js (interface), samples.js, theme.js (theme before first paint)
scripts/build.mjs      single-file build with hash-pinned CSP
scripts/sources.mjs    citation list in RULES.md
scripts/verify-sources.mjs  checks every quoted passage against its source
tests/                 node:test suite
RULES.md               every check, condition and severity
```

When you change a rule in `src/core/`, update `RULES.md` in the same change.

## License

MIT
