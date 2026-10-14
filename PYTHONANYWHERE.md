# Deploy BrandShield Sentinel on PythonAnywhere

This guide deploys the current Flask + SQLite prototype to a PythonAnywhere web app. It does not add live social, app-store, payment, or threat-intelligence integrations.

## 1. Upload the application

Create a PythonAnywhere account and upload the project files using the **Files** page, or clone the project from a Git repository in a Bash console. Keep the project under your home directory, for example:

```text
/home/YOUR_USERNAME/BrandShield_Sentinel_Pro
```

Do not upload `.venv`, `.env`, or a local `sentinel.db`. Start with a fresh production database so the built-in demo account and synthetic workspace are not carried to the public site.

## 2. Create a virtual environment

In **Web → Add a new web app**, choose **Manual configuration** and a Python version available in your account. Use the same Python version in a PythonAnywhere Bash console:

```bash
mkvirtualenv --python=/usr/bin/python3.13 brandshield-venv
workon brandshield-venv
cd ~/BrandShield_Sentinel_Pro
pip install -r requirements.txt
```

Replace `python3.13` with the version you selected if PythonAnywhere shows a different executable. In the Web tab, set **Virtualenv** to:

```text
/home/YOUR_USERNAME/.virtualenvs/brandshield-venv
```

## 3. Configure the WSGI file and secrets

Generate a long random secret in the PythonAnywhere Bash console:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Open the WSGI configuration file linked from the **Web** tab. Replace its contents with the following, substituting your PythonAnywhere username and the generated secret. Keep this file private; do not put the secret in the project or commit it.

```python
import os
import sys

project_home = "/home/YOUR_USERNAME/BrandShield_Sentinel_Pro"
data_home = "/home/YOUR_USERNAME/.brandshield-data"
os.makedirs(data_home, mode=0o700, exist_ok=True)

if project_home not in sys.path:
    sys.path.insert(0, project_home)

os.environ["SENTINEL_ENV"] = "production"
os.environ["SENTINEL_SECRET_KEY"] = "PASTE_THE_GENERATED_RANDOM_SECRET_HERE"
os.environ["SENTINEL_DB_PATH"] = os.path.join(data_home, "sentinel.db")

from app import app as application
```

The production setting requires a configured secret, enables secure session cookies over HTTPS, enables CSRF protection on form submissions, and does not create the built-in demo account on a fresh database. On first load the app creates its SQLite schema in the private data directory; register your own account using **Create an account**.

## 4. Configure static files and reload

In the **Web** tab, optionally add a static files mapping:

| URL | Directory |
| --- | --- |
| `/static/` | `/home/YOUR_USERNAME/BrandShield_Sentinel_Pro/static/` |

Click **Reload** for your web app. Visit the `your-username.pythonanywhere.com` address shown in the Web tab, create your account, and verify sign-in, candidate entry, CSV import, the scam-network page, and CSV export.

## 5. Backups and operating notes

- Back up `/home/YOUR_USERNAME/.brandshield-data/sentinel.db` regularly. Do not put the database in a temporary directory.
- Test a backup restore before relying on it. SQLite is suitable for this single-instance prototype, not a high-volume multi-worker service.
- Keep `.env`, the WSGI secret, and the database private. Rotate the session secret deliberately; changing it signs out existing sessions.
- PythonAnywhere deployment does not configure platform integrations. The app only analyzes manually entered or imported authorized observations.
- Risk scores and graph links are review aids, not proof of fraud or common ownership. The supplied sample data is synthetic.
- This is still a prototype: review account recovery, rate limiting, logging, retention and privacy requirements before using sensitive or business-critical data.

## Troubleshooting

- **Import error / application failed to start:** verify the WSGI `project_home` and that the Web tab uses the virtualenv where `requirements.txt` was installed. Read the error log linked from the Web tab.
- **Missing secret error:** set `SENTINEL_SECRET_KEY` in the WSGI config and click Reload.
- **CSRF token missing:** use the forms rendered by the app, enable browser cookies, and reload the page after deploying. All state-changing forms require a CSRF token.
- **Database cannot be opened:** verify `data_home` exists and is writable by your PythonAnywhere user; keep the SQLite database out of read-only/static folders.
