# WebGGuard 🛡️

A full-stack URL threat-intelligence tool built as an educational reference project.

WebGGuard accepts a URL, queries the [VirusTotal v3 API](https://developers.virustotal.com/reference/overview), and runs the results through a rule-based scoring engine to determine whether the site is **safe**, **suspicious**, or **malicious**.

---

## Tech Stack

| Layer    | Technology               |
|----------|--------------------------|
| Backend  | Go (stdlib only, no framework) |
| Frontend | React + Vite             |
| API      | REST / JSON              |
| Data     | VirusTotal v3 API        |

---

## Project Structure

```
webgguard/
├── backend/
│   ├── cmd/server/main.go               ← Entry point; wires everything together
│   ├── internal/
│   │   ├── api/scan.go                  ← HTTP handler (thin orchestration layer)
│   │   ├── services/virustotal.go       ← VirusTotal API client
│   │   ├── rules/verdict.go             ← ★ Rule engine / scoring logic
│   │   ├── models/scan.go               ← Shared data structures
│   │   └── utils/url.go                 ← URL normalization & encoding
│   └── go.mod
│
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── ScanForm.jsx             ← URL input + submit button
    │   │   └── ResultCard.jsx           ← Verdict display + VT stats
    │   ├── services/api.js              ← All backend fetch() calls
    │   ├── App.jsx                      ← Root component + state
    │   ├── App.css                      ← All styles
    │   └── main.jsx                     ← React entry point
    ├── index.html
    ├── package.json
    └── vite.config.js
```

---

## How to Run

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)
- [Node.js 18+](https://nodejs.org/)
- A free [VirusTotal API key](https://www.virustotal.com/gui/join-us)

---

### 1. Run the Backend

```bash
cd backend

# Set your VirusTotal API key
export VT_API_KEY="your_api_key_here"

# Start the server (runs on http://localhost:8080)
go run ./cmd/server
```

You should see:
```
[START] WebGGuard backend listening on http://localhost:8080
[INFO]  Endpoint: POST http://localhost:8080/scan
```

**Test it with curl:**
```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

---

### 2. Run the Frontend

```bash
cd frontend

# Install dependencies (first time only)
npm install

# Start the dev server (runs on http://localhost:5173)
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## API Reference

### `POST /scan`

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "verdict":    "suspicious",
  "riskScore":  42,
  "confidence": 63,
  "stats": {
    "malicious":  3,
    "suspicious": 2,
    "undetected": 55,
    "harmless":   30,
    "timeout":    2
  }
}
```

| Field        | Type   | Description                                   |
|--------------|--------|-----------------------------------------------|
| `verdict`    | string | `safe`, `suspicious`, or `malicious`          |
| `riskScore`  | int    | 0 (clean) → 100 (dangerous)                   |
| `confidence` | int    | 0–100%; how many engines gave a clear verdict |
| `stats`      | object | Raw detection counts from VirusTotal          |

### `GET /health`
Returns `{"status":"ok"}` — used for liveness checks.

---

## Where the Security Logic Lives

### VirusTotal Service → `backend/internal/services/virustotal.go`

Responsible for:
- Building the VT v3 API request (base64url URL encoding)
- Parsing the `last_analysis_stats` from the response
- Returning clean `VirusTotalStats` to the handler

### Rule Engine → `backend/internal/rules/verdict.go`

This is **the core of WebGGuard**. The scoring algorithm:

```
1. totalEngines = malicious + suspicious + undetected + harmless + timeout
2. detectionRatio = (malicious + suspicious) / totalEngines
3. baseScore = detectionRatio × 100
4. weightedPenalty = (malicious × 3) + (suspicious × 1)
5. rawScore = (baseScore + weightedPenalty) / 2     [clamped 0–100]

Verdict thresholds:
  rawScore ≥ 60  → malicious
  rawScore ≥ 20  → suspicious
  rawScore < 20  → safe

Confidence = (malicious + suspicious + harmless) / totalEngines × 100
```

The weights and thresholds are named constants at the top of `verdict.go` — easy to tune.

---

## How to Extend the System

### Add a New Scoring Signal

Edit `backend/internal/rules/verdict.go`:
- Add a new weight constant
- Incorporate it into the `Evaluate()` function
- Update the `ScanResult` model if you need to expose new fields

### Add Domain Reputation Lookup

Create `backend/internal/services/domainreputation.go` following the same pattern as `virustotal.go`. Then call it from the handler in `api/scan.go` and pass the extra signal into `rules.Evaluate()`.

### Add Result History

In the frontend, add a `history` array to `App.jsx` state:
```js
const [history, setHistory] = useState([]);
// after each scan:
setHistory(prev => [{ url: lastUrl, result: data }, ...prev].slice(0, 10));
```
Then render `<HistoryList />` below the result card.

### Add Caching (Backend)

In `virustotal.go`, check an in-memory map (or Redis) before calling the VT API:
```go
if cached, ok := cache[urlID]; ok { return cached, nil }
```
This avoids redundant API calls and stays within the free-tier rate limit.

### Switch to a Database

Replace the stateless handler with a `ScanRepository` interface that stores results in PostgreSQL or SQLite. This enables history, analytics, and alerting.

---

## Environment Variables

| Variable     | Required | Description                          |
|--------------|----------|--------------------------------------|
| `VT_API_KEY` | ✅ Yes   | Your VirusTotal v3 API key           |
| `PORT`       | No       | Backend port (default: `8080`)       |
| `VITE_API_URL` | No     | Frontend backend URL (default: `http://localhost:8080`) |

---

## Learning Path

If you're studying this codebase, read the files in this order:

1. `models/scan.go` — understand the data shapes
2. `utils/url.go` — URL normalization
3. `services/virustotal.go` — external API integration
4. `rules/verdict.go` — the scoring engine ← **most important**
5. `api/scan.go` — how the HTTP layer ties it together
6. `cmd/server/main.go` — startup + wiring
7. `frontend/src/services/api.js` — frontend ↔ backend contract
8. `frontend/src/App.jsx` → components — UI state flow
