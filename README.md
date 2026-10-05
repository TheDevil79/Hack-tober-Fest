# PatchLens - Security Scanner & Backend

PatchLens is a defensive security posture scanner built with Express.js. It performs non-invasive security checks including TLS configuration inspection, HTTP security header audits, passive technology fingerprinting, and correlated OSV vulnerability advisory queries.

---

## 🛡️ Defensive Scanning Capabilities

1. **URL Validation & SSRF Protection**:
   - Rejects loopback (`127.0.0.0/8`, `::1`), private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), carrier-grade NAT (`100.64.0.0/10`), link-local, and cloud metadata (`169.254.169.254`, `metadata.google.internal`).
   - Resolves DNS and validates all resolved IPv4 and IPv6 addresses before connecting.
   - Enforces SSRF validation on every hop of HTTP redirect chains.

2. **TLS / HTTPS Scanner**:
   - Audits HTTPS availability, TLS certificate validity, expiration dates, remaining validity days, and protocol versions (TLS 1.2 / TLS 1.3).
   - Generates alerts for expired certificates, self-signed certificates, and weak protocol versions.

3. **HTTP Security Headers Scanner**:
   - Evaluates defensive response headers against deterministic severity rules:
     - `Content-Security-Policy` (Missing -> High severity)
     - `Strict-Transport-Security` (Missing on HTTPS -> Medium severity)
     - `X-Content-Type-Options` (Missing / not `nosniff` -> Medium severity)
     - `X-Frame-Options` (Missing / non-standard -> Medium severity)
     - `Referrer-Policy` (Missing -> Low severity)
     - `Permissions-Policy` (Missing -> Low severity)

4. **Passive Technology Fingerprinting**:
   - Non-invasive analysis of `Server`, `X-Powered-By`, framework headers, meta tags, and script markers.
   - Assigns strict confidence levels (`high`, `medium`, `low`).
   - Extracts versions **only** when reliable, explicit evidence is observed.

5. **OSV Vulnerability Correlation**:
   - Queries the Open Source Vulnerability (OSV) database **only** when a component and a reliable version are identified.
   - Never infers CVEs merely from software names without verified versions.

6. **Safety & Operational Guards**:
   - Helmet HTTP headers enabled.
   - Rate limiting on `/api/scan`.
   - Structured JSON logging with automatic redaction of keys, tokens, passwords, and sensitive headers.
   - Bounded response body sizes and timeout controls.
   - Bounded scan concurrency semaphore.
   - Graceful partial error recovery (returns module errors without crashing).

---

## 🚀 Getting Started

### 1. Install Dependencies
```bash
cd server
npm install
```

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp ../.env.example .env
```

Available configuration options:
```env
PORT=5000
ALLOWED_ORIGINS=*
SCAN_TIMEOUT_MS=10000
MAX_SCAN_CONCURRENCY=5
OSV_BASE_URL=https://api.osv.dev/v1/query
MONGODB_URI=
MONGODB_DB=patchlens
GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.8-flash
GEMINI_FALLBACK_MODELS=gemini-3.6-flash,gemini-3.5-flash-lite
AI_PROVIDER=gemma
GEMMA_MODEL=gemma-4-26b-a4b-it
GEMMA_FALLBACK_MODELS=gemma-4-31b-it
EMBEDDING_MODEL=gemini-embedding-001
VECTOR_INDEX=knowledge_vector_index
AUTH_USERNAME=your-admin-username
AUTH_PASSWORD=use-a-strong-unique-password
AUTH_SECRET=use-at-least-32-random-characters
AUTH_SESSION_TTL_SECONDS=28800
```

PatchLens requires an authenticated browser session before scanner or intelligence APIs can be used. New accounts are stored in MongoDB with salted scrypt password hashes. `AUTH_USERNAME` and `AUTH_PASSWORD` remain optional as a legacy administrator login. Keep real credentials only in your local `.env` file or your hosting provider's secret settings—never commit them. The server issues a signed, expiring bearer token, and the React client keeps it in `sessionStorage` for the current browser session.

Set `AI_PROVIDER=gemma` to generate remediation with hosted Gemma through the Gemini API. The configured Gemini models remain automatic fallbacks when Gemma is unavailable. Set `AI_PROVIDER=gemini` to reverse that order.

### 3. Start the Server
```bash
npm start
```
The server will start listening on port `5000` (or `PORT` specified in `.env`).

### 4. Start the React frontend for development

In a second terminal:

```bash
cd client
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies API requests to the backend on port `5000`.

For a single-process demo, build the frontend first and then start the backend:

```bash
cd client
npm install
npm run build
cd ../server
npm start
```

Open `http://localhost:5000`. Express automatically serves the built interface from `client/dist`.

---

## 📡 API Reference

### Health Check
```http
GET /health
# GET /api/health is also supported
```

**Response (`200 OK`)**:
```json
{
  "status": "UP",
  "service": "PatchLens Scanner Backend"
}
```

### Authentication

Create an account (requires MongoDB):

```http
POST /api/auth/signup
Content-Type: application/json

{
  "displayName": "Vasu Shukla",
  "username": "vasu",
  "email": "vasu@example.com",
  "password": "StrongPass123"
}
```

Sign in with either the username or email:

```http
POST /api/auth/login
Content-Type: application/json

{
  "identifier": "your-username-or-email",
  "password": "your-password"
}
```

Successful login returns an expiring bearer token. Send it with protected requests:

```http
Authorization: Bearer <token>
```

Use `GET /api/auth/session` to validate an existing session. Scanner and intelligence endpoints return `401` without a valid session, and login attempts are rate limited.

---

### Run Security Scan
```http
POST /api/scan
Content-Type: application/json

{
  "url": "https://authorized-demo.example"
}
```

The legacy `target` request field is also supported. Only scan targets you own or are explicitly authorized to assess.

**Response (`200 OK`)**:
```json
{
  "scanId": "scan_1727878000000_abcde",
  "target": "https://authorized-demo.example",
  "timestamp": "2026-10-02T14:00:00.000Z",
  "tls": {
    "valid": true,
    "protocol": "TLSv1.3",
    "issuer": "Let's Encrypt",
    "validTo": "2026-12-31T23:59:59.000Z",
    "daysRemaining": 90
  },
  "technologies": [
    {
      "name": "Express",
      "confidence": "medium"
    },
    {
      "name": "Apache",
      "confidence": "high",
      "version": "2.4.51"
    }
  ],
  "findings": [
    {
      "id": "header-csp",
      "category": "security_header",
      "name": "Content-Security-Policy",
      "status": "missing",
      "severity": "high",
      "evidence": "Header not observed in response",
      "remediation": {
        "explanation": "...",
        "whyItMatters": "...",
        "remediation": "...",
        "implementation": "...",
        "verification": ["..."],
        "confidence": "high",
        "limitations": "...",
        "sources": []
      }
    },
    {
      "id": "header-x-frame-options",
      "category": "security_header",
      "name": "X-Frame-Options",
      "status": "missing",
      "severity": "medium",
      "evidence": "Header not observed in response"
    }
  ]
}
```

If MongoDB or Gemini is unavailable, the deterministic scanner result is still returned. The response includes persistence or remediation availability metadata instead of failing the complete scan.

### Intelligence endpoints

```http
GET  /api/intelligence/scans/:id
GET  /api/intelligence/history?target=https%3A%2F%2Fexample.test
POST /api/intelligence/compare
POST /api/intelligence/remediate
```

Seed MongoDB knowledge documents and embeddings after configuring MongoDB and Gemini:

```bash
npm run seed:knowledge
```

---

## 🧪 Running Tests

Run the full automated test suite:
```bash
npm test
```

Or run individual test modules:
```bash
node tests/urlPolicy.test.js
node tests/headerScanner.test.js
node tests/techScanner.test.js
node tests/advisoryScanner.test.js
node tests/tlsScanner.test.js
node tests/orchestrator.test.js
node tests/api.test.js
node tests/intelligence.test.js
```

---

## 🏗️ Architecture & Ownership Boundary

```
server/
  src/
    app.js                      # Express application, middleware & rate limiting
    server.js                   # Server initialization
    routes/
      scanRoutes.js             # API route endpoints (/api/scan, /api/health)
      intelligence.js           # History, comparison, and remediation endpoints
    ai/
      gemini.js                 # Grounded remediation and embedding client
    db/
      mongo.js                  # Optional MongoDB connection lifecycle
    services/
      scans.js                  # Persistence, enrichment, history, and comparison
      rag.js                    # Vector retrieval with local keyword fallback
      remediation.js            # Retrieval + Gemini remediation + cache
    data/
      knowledge.json            # Curated local fallback knowledge
    scanners/
      scanOrchestrator.js       # Module orchestration & partial error handling
      tlsScanner.js             # TLS/HTTPS inspection
      headerScanner.js          # Security header analysis
      techScanner.js            # Passive technology fingerprinting
      advisoryScanner.js        # OSV advisory integration
    security/
      urlPolicy.js              # SSRF protection & private network filter
    utils/
      httpClient.js             # Bounded HTTP client with safe redirect tracing
      normalizeFinding.js       # Finding normalization & deterministic severity matrix
    logging/
      logger.js                 # Structured logger with sensitive-data redaction
```

The `client/` directory contains the React/Vite interface with scan progress, severity summaries, findings and remediation, scan history, before/after comparison, rescan controls, and downloadable/printable reports.
