# BrandShield Sentinel — Full-stack local MVP

A working, responsive digital-risk-protection dashboard for social profile and app-store candidate triage.

## Features that work
- Account sign-up and sign-in (passwords are hashed); isolated brand workspace per account.
- Analyst profile with editable display name, sign-in email, and session sign-out.
- Brand profile editing and official-asset registry.
- False-Positive Shield: exact registered official identifiers are skipped on manual add/import.
- Social and app-store candidate management, search, filters, confidence/risk scoring and explainable rationale.
- Re-score saved candidates using the local heuristic engine.
- Investigation status updates, evidence notes, evidence vault.
- CSV import/export with duplicate and official-asset suppression, row validation, and clear import summaries.
- Paginated, filterable monitoring with highest-risk cases prioritized first.
- Workspace-wide risk summaries, campaign-cluster hints, scan history, settings, responsive UI.
- Scam Network Intelligence: correlate exact observed URLs, payment URLs, phone numbers, domains, and app publishers across cases; inspect provenance and export linked evidence.
- SQLite persistence; records survive app restarts.

## Quick start
Requires Python 3.10+.

### macOS / Linux
```bash
cd BrandShield_Sentinel_Pro
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Windows PowerShell
```powershell
cd BrandShield_Sentinel_Pro
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

CSV imports are limited to 5 MB and 10,000 rows per upload. Repeated records, registered official identifiers, and invalid rows are skipped and counted in the completion summary.

## Deploy on PythonAnywhere
See [PYTHONANYWHERE.md](./PYTHONANYWHERE.md) for the WSGI setup, virtual environment, secure production secret, SQLite storage, and reload steps. Production mode requires `SENTINEL_SECRET_KEY`, uses secure session cookies, enables CSRF protection, and does not seed the demo account in a fresh database.

### Scam Network Intelligence
Open **Scam network** from the workspace navigation. The module extracts identifiers from candidate URLs, descriptions and app publisher fields already in the workspace, then builds evidence-backed case links. The graph shows observed field, timestamp and source-quality metadata for each shared identifier. Link strength is an explainable heuristic—not a probability, attribution, or finding of wrongdoing. Cases marked false positive remain visible but are excluded from links. Common platform domains and `.example` demo domains do not create domain-only links; indicators shared by more than 25 cases are suppressed as broad infrastructure. Use **Export investigation** to download linked evidence as CSV. The sample import includes two explicitly synthetic records sharing an illustrative payment URL so you can demonstrate the graph; do not treat them as real observations. No network requests are made to the listed candidate sources.

Correlation weights are visible in the graph view: payment URL 94, exact URL or phone 90, domain 55 and publisher 48. A small adjustment applies the lower provenance weight across the two records (manual/CSV 0.60, built-in synthetic demo 0.35, other source 0.50). These values are transparent but uncalibrated prioritization heuristics, not probabilities or trust ratings. Add optional `observed_at` values in manual entry or CSV as timezone-aware ISO 8601 (for example `2026-10-14T08:00:00Z`). When a source timestamp was not provided, the graph explicitly labels the record-capture time instead.

### Run workflow checks
```bash
python -m unittest discover -s tests
```

### Demo login
- Email: `demo@sentinel.local`
- Password: `SentinelDemo!26`

You can create a separate account using Sign up. The first launch creates a demo workspace with clearly illustrative records.

## CSV import format
Required columns: `channel,name`
Optional columns: `url,developer,description,logo_match,observed_at`

Example:
```csv
channel,name,url,developer,description,logo_match,observed_at
Social,Northstar Support Desk,https://social.example/northstar-help,,Urgent account recovery,0,2026-10-14T08:00:00Z
App Store,Northstar Wallet Plus,https://store.example/apps/northstar-wallet,Unknown Studio,Companion wallet,1,
```
`channel` accepts `Social` or `App Store` (also `app` / `store`).

## Important boundaries
This is a functional local MVP, not a production threat-intelligence service. It does **not** crawl social networks or app stores and it does not call platform APIs. The scan button re-scores records already stored in your workspace. Sample records and demo metrics are synthetic. Candidate risk is a triage signal, not a finding of fraud or malicious intent. Similarity alone is not proof.

To enable live monitoring, add approved connectors for the exact sources you have permission to access, respect platform terms and rate limits, store source URLs/timestamps, and record connector health/errors. Logo similarity currently uses a manually marked `logo_match` field; it does not run image embeddings or perceptual hashing.

## Before internet deployment
1. Set `SENTINEL_ENV=production` and a long random `SENTINEL_SECRET_KEY`; use HTTPS and secure session cookies.
2. Back up the SQLite database and verify recovery. Migrate to managed PostgreSQL if concurrency or scale requires it.
3. Add rate limits, account recovery and audit logging before handling sensitive or business-critical data.
4. Review privacy, retention, authorization and security with your team.
5. Implement and test approved source connectors; do not present synthetic sample records as live findings.
