# Gopal Treats Admin Dashboard (separate service)

This is the separate verification + admin dashboard project. It does not modify the public storefront.

## Render settings
- Repository: this private repository
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Persistent disk: mount at `/var/data` (1 GB)
- Environment: `DATA_DIR=/var/data`
- Set `ADMIN_PASSWORD` to a unique password of 14+ characters in Render.
- Set `FLASK_SECRET_KEY` to a random value of 32+ characters in Render.

The included `render.yaml` describes the service and persistent disk. If creating the service manually, enter the settings above. Never commit secrets or `visits.db`.

## Local run (Windows)
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
set ADMIN_PASSWORD=your-private-local-password
set FLASK_SECRET_KEY=your-long-random-local-secret
python app.py
```

## Visitor notice and data
The verification screen explains the information recorded and requires a separate checkbox and Continue click. Only after that submission is a visit recorded. The record contains the address presented by the server, user-agent string and UTC timestamp. IP addresses are not precise GPS location or identity. Shared networks, VPNs and proxies can affect the address observed. Keep the repository private, restrict dashboard access, use records only for the disclosed educational purpose, and delete them when no longer needed.
