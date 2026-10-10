# PhishGuard

**Check before you click.** PhishGuard analyzes suspicious links and messages for phishing indicators, produces an explainable 0–100 risk score, and recommends what to do next.

> PhishGuard looks for common phishing signs. It cannot detect every threat and cannot guarantee that a link or message is safe.

PhishGuard is intentionally **stateless**: there is no database, no accounts, and nothing is saved. Every submission is analyzed and the result returned in the same request; nothing about what you paste in is kept once the response is sent.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # then set SECRET_KEY
python run.py                    # http://127.0.0.1:5000
```

Generate a secret key with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

`SECRET_KEY` is only used to sign the session cookie that CSRF protection relies on — there's no user data behind it.

## Usage

1. Open the app and choose **A link** or **A message**.
2. Paste the content and click **Analyze Now**.
3. Read the risk score (0–100), the level (LOW/MEDIUM/HIGH/CRITICAL), the specific findings behind it, and the recommended action.

A link is only ever parsed as text — PhishGuard never fetches, opens, or resolves a submitted URL.

## AI second opinion (optional)

PhishGuard's core score always comes from the deterministic rule engine above — that never changes. On top of it, you can turn on an **optional local AI second opinion**: a small language model running on your own machine via [Ollama](https://ollama.com), asked to judge the same content independently.

**It's off by default.** With no setup, PhishGuard runs exactly as described everywhere else in this README, with no AI call and no Ollama dependency.

To turn it on:

```bash
# 1. Install Ollama: https://ollama.com/download
# 2. Pull a small, fast model (1.5B runs fine on a CPU-only laptop)
ollama pull qwen2.5:1.5b
# 3. Make sure Ollama is running (it usually starts itself after install)
ollama serve   # if it isn't already running

# 4. In your .env:
PHISHGUARD_AI_ENABLED=1
OLLAMA_URL=http://127.0.0.1:11434/api/chat
OLLAMA_MODEL=qwen2.5:1.5b
OLLAMA_TIMEOUT=45
```

Restart the app and the result page will show an **"AI second opinion"** section below the main findings.

**How it's kept honest, not just bolted on:**

- **Independent, never blended.** The model is shown only the raw URL or message — never PhishGuard's score or findings — so it reaches its own conclusion rather than rationalizing one we already gave it. Its opinion is displayed in a clearly separate, clearly labeled box and **never changes the risk score, level, or findings above it**.
- **Always optional at the call site.** `app/services/ai_service.py` never raises — every failure (Ollama not running, a timeout, a malformed reply) comes back as a normal result with `available=False` and a plain-English reason. `analysis_service.py` additionally wraps the call in a last-resort `try/except`, so even a bug in the AI layer can't take down the page. You'll always get the deterministic result; the AI box either shows an opinion or says plainly that it wasn't available.
- **Local only.** Requests go to `OLLAMA_URL`, which defaults to `127.0.0.1`. This feature never sends your submitted content to a cloud AI service.
- **Any Ollama chat model works** — swap `OLLAMA_MODEL` for a larger one (`llama3.1:8b`, etc.) if you have the hardware; `qwen2.5:1.5b` is the default because it's small enough to run comfortably on a CPU-only machine.

See `tests/test_ai_service.py` (the HTTP client, mocked — no real Ollama needed to run the tests) and `tests/test_ai_route.py` (the result page with AI on, off, and failing) for how this is verified.

## Architecture

```
app/
  __init__.py          application factory: CSRF, logging, security headers, error handlers
  errors.py            centralized 400/404/405/413/500 + CSRF error handling
  extensions.py        the one shared extension instance (CSRFProtect)
  logging_config.py    stdout logging setup
  routes/
    main.py            landing page
    analysis.py        POST /analyze — thin: validation + rendering only
  services/
    errors.py           InvalidInput / FeatureNotAvailable
    findings.py          the Finding record every analyzer produces
    risk_engine.py        turns findings into a 0-100 score + level (the core logic)
    url_analyzer.py        analyzes a URL as text
    message_analyzer.py    analyzes free-text messages, including any links inside them
    ai_service.py           optional local-AI second opinion via Ollama (off by default)
    analysis_service.py    glues a scan_type + content to the right analyzer + risk_engine (+ AI, if enabled)
  templates/           Jinja2 templates (no client-side framework)
  static/              one CSS file, one small JS file (no build step)
config.py              environment-driven configuration (dev/production/testing)
wsgi.py                production entry point (gunicorn)
run.py                 development entry point (flask dev server)
```

### Key decisions

- **No database, no accounts.** The MVP's job is to analyze and explain, not to manage users. This keeps the attack surface small (no password storage, no session-fixation surface beyond CSRF, no data-retention question) and the app trivial to run anywhere Python runs.
- **URLs are analyzed as text and never fetched**, which avoids server-side request forgery — a submitted `http://169.254.169.254/...`-style URL is just a string to PhishGuard, never a request it makes.
- **Explainable, corroborated scoring:** every score is backed by named findings (`app/services/risk_engine.py`). A single keyword or a single isolated signal can never produce a HIGH or CRITICAL result — risk escalates only when independent *categories* of signal (transport, domain, structure, wording, impersonation, etc.) appear together. This is enforced in code (`SINGLE_CATEGORY_MAX`, `KEYWORD_ONLY_MAX` in `risk_engine.py`), not just in the wording, and is covered by dedicated tests.
- **CSRF protection** (Flask-WTF `CSRFProtect`) is on by default; it only needs the signed session cookie Flask already provides, no server-side session store.
- **Flask over a heavier framework** to keep this small and easy to read end to end.
- Minimal, resident data: nothing persists past the response, so there's nothing to secure at rest, migrate, or back up.

## How scoring works

Every score is the sum of explained findings, so nothing is a black box.

| Area (category) | Example finding | Points |
|---|---|---|
| Connection | Plain `http` | 15 |
| Domain/address | IP address instead of domain (incl. disguised forms) | 25 |
| Domain/address | Unusual port / 3+ subdomains | 10 each |
| Link structure | `@` trick, look-alike characters | 15 each |
| Link structure | Unusual encoding, embedded second URL | 10 each |
| Link structure | Very long link, 3+ hyphens in domain | 5 each |
| Wording | Login, password/code, verification words in host or path | 10 each |
| Parameters | Password/OTP/PIN-style field in query | 15 |
| Parameters | Redirect parameter pointing to another address | 10 |
| Impersonation | Known brand name inside an unrelated domain | 20 |
| Message content | Credential/payment requests, urgency, threats, "too good to be true" offers | 10–20 each |
| Message content | Sender claims a brand but the sender domain doesn't match | 15 |

Weights live in `WEIGHTS` in `url_analyzer.py` and `message_analyzer.py`.

**Corroboration rules** (`app/services/risk_engine.py`):

- Each independent category beyond the first adds **+10**, reported as its own finding ("Several independent warning signs together") so the escalation itself is explained, not hidden.
- Only one category present: the score is capped at **59**, so it can never reach HIGH or CRITICAL from one kind of signal alone.
- Only wording (keywords) present: capped at **29**, so wording alone never reaches MEDIUM.
- Final score is capped at 100. Levels: 0–29 LOW, 30–59 MEDIUM, 60–79 HIGH, 80–100 CRITICAL.

This directly satisfies the requirement that no single isolated keyword match can, by itself, produce a HIGH or CRITICAL result — see `tests/test_risk_engine.py` for the test cases that pin this down.

### URL analyzer notes

- Links are parsed as text only. Nothing is fetched or resolved.
- Only `http`/`https` links are accepted; `javascript:`, `data:`, `ftp:` and similar are rejected with a clear message.
- A link pasted without a scheme is analyzed as a web address, with no HTTP penalty.
- The registered domain is found with a small built-in list of two-part suffixes (e.g. `co.uk`, `com.ng`) rather than the full Public Suffix List. This can be swapped for a full list later.
- The brand list is a short starter set. Brand detection looks for a brand name inside an unrelated domain; true typosquatting (`paypa1.com`) would be part of a future reputation layer (see Future Work).
- Submitted links are always shown back as plain text, never as clickable links.

### Message analyzer notes

- Looks for: credential/payment requests, urgency, threats, generic greetings, "too good to be true" offers, attachment lures, requests to switch to an unusual contact channel, and odd formatting.
- Any link found in the message text is run through the URL analyzer on its own; its worst finding is folded in as one `suspicious_link` finding, and known shorteners (bit.ly, tinyurl.com, etc.) are flagged separately.
- If the message names a well-known brand (PayPal, Microsoft, a bank, ...) and also includes a `From:` line or email address, a mismatch between the claimed brand and the sender's actual domain is flagged.
- A message under 10 characters is rejected as too short to assess.
- As with links, the message text and any URLs inside it are only ever displayed as plain text, never fetched or rendered as clickable.

## Security

- **CSRF protection** on the analyze form via Flask-WTF; a missing or invalid token is rejected with a friendly message, not a crash.
- **Security headers** on every response: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and a restrictive `Content-Security-Policy` (`default-src 'self'`, no inline scripts). `Strict-Transport-Security` is added automatically once `SESSION_COOKIE_SECURE` is on (i.e. in production).
- **Input limits:** `MAX_INPUT_LENGTH` (default 5000 characters, configurable) is enforced before analysis; `MAX_CONTENT_LENGTH` (64 KB) rejects oversized request bodies outright with a friendly 413 page instead of a server error.
- **No secrets in source.** `SECRET_KEY` and all other config come from environment variables (`.env` locally, real environment variables in production); `.env` is gitignored.
- **Centralized, generic error handling** (`app/errors.py`): 400/404/405/413/500 all return a plain page with no stack trace or internal detail, and server errors are logged server-side instead.
- **Production refuses to start without `SECRET_KEY`** (`ProductionConfig.validate()`), so a misconfigured deployment fails loudly at startup rather than running insecurely.
- **Dependencies** are pinned in `requirements.txt`; review with `pip list --outdated` and `pip-audit` (not installed by default) before a production deploy.

## Testing

```bash
python -m pytest -q
python -m pytest --cov=app --cov-report=term-missing   # coverage report
```

As of this build: **118 tests, 97% overall coverage**, with the core analysis engine (`risk_engine.py`, `url_analyzer.py`, `message_analyzer.py`, `findings.py`) at 97–100% and the AI service at 92% — all well above the 80% target for the core engine. Every AI test mocks the HTTP call, so the full suite runs with no Ollama installation needed.

Test files:
- `test_risk_engine.py` — scoring, level boundaries, the single-category and keyword-only caps that stop one signal from reaching HIGH/CRITICAL.
- `test_url_analyzer.py` — every URL finding, plus malformed/unsupported input handling (`javascript:`, bad hosts, missing scheme, etc.).
- `test_message_analyzer.py` — every message finding, sender/brand mismatch, embedded-link handling.
- `test_analyze_route.py` — the HTTP layer: normal results, error responses (400/413), escaping of user content, the message-vs-url path.
- `test_security.py` — CSRF enforcement (rejected without a token, accepted with one), security headers, generic error pages, production config validation.
- `test_ai_service.py` — the Ollama HTTP client in isolation: success, timeout, connection refused, bad JSON, non-200 status — all mocked.
- `test_ai_route.py` — the AI feature wired into `/analyze`: off by default, shown when enabled, and the page still renders the full deterministic result when the AI call is unavailable or raises unexpectedly.
- `test_main.py` — the landing page.

## Deployment

1. Set real environment variables (never commit them): `SECRET_KEY`, `FLASK_ENV=production`, optionally `MAX_INPUT_LENGTH`.
2. Install dependencies: `pip install -r requirements.txt`.
3. Run with a production WSGI server, not the Flask dev server:
   ```bash
   gunicorn 'wsgi:app' --bind 0.0.0.0:$PORT --workers 2 --timeout 30
   ```
   A `Procfile` is included for platforms that use one (Render, Railway, Heroku-style).
4. Put it behind HTTPS (most platforms terminate TLS for you; if you manage your own, use a reverse proxy like nginx/Caddy). `SESSION_COOKIE_SECURE` and the `Strict-Transport-Security` header both activate automatically under `ProductionConfig`.
5. Logs go to stdout — capture them with whatever your platform provides (no log files or rotation to configure).
6. There is no database to provision or migrate.

`ProductionConfig` enforces `DEBUG = False` and refuses to start if `SECRET_KEY` is unset, so a misconfigured deploy fails at startup instead of serving insecurely.

## Future work

Deliberately out of scope for this MVP, compatible with the current architecture if added later:

- **Accounts and saved history**, if a future version needs them — would layer on top of this stateless core without changing the analyzers.
- **Domain reputation / threat-intel lookups** (Safe Browsing, VirusTotal, WHOIS domain age, look-alike/typosquat detection) as an optional, feature-flagged service that augments — never replaces — the deterministic findings here, the same pattern used for the AI second opinion above.
- **Folding the AI opinion into the score itself** (rather than showing it as a separate box) — deliberately not done: keeping it fully separate is what lets it fail, time out, or be disabled without ever affecting the auditable rule-based score.
- Browser extension, email integration, QR-code/screenshot analysis, rate limiting, API access.

None of these are needed for PhishGuard to work today — the app is fully functional on its own, as shipped.
