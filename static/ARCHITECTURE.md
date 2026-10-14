# Architecture notes

```text
Browser
  └── Flask routes + Jinja templates + responsive CSS/JS
        ├── Authentication (Werkzeug password hashing + session cookie)
        ├── Local heuristic scoring (name, description terms, manual logo flag, developer mismatch signal)
        ├── False-Positive Shield (exact registered-asset matching)
        └── SQLite persistence
              ├── users / brands / assets
              ├── candidates / evidence
              ├── scan history / settings

Future connectors (not implemented):
  ├── Authorized social platform APIs / permitted feeds
  ├── App-store APIs / permitted metadata sources
  ├── Image perceptual hashing or embeddings for logo comparison
  ├── Queue / scheduler + retries + source-health monitoring
  └── Email / webhook notifications
```

Current implementation deliberately labels live connectors as unavailable. No scraping or platform API calls are made.
