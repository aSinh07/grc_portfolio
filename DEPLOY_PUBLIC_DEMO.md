# GRC Nexus V4 — public, password-free demo

The public portfolio (`/`) and GRC Lab (`/workspace`) open without a password. `/api/state` returns **synthetic demonstration data only**, not the private database or uploaded evidence.

**Owner Studio (`/owner`) and every data-changing API remain password protected** with `GRC_ADMIN_PASSWORD`. This is intentional; making uploads and edits public would let strangers alter the site.

The demo lab is read-only for anonymous visitors. Some edit/upload buttons remain visible in the UI but will be rejected by the server; do not enter real data into the demo.

## Free deployment

1. Unzip and open the folder containing `app.py`.
2. Create a private GitHub repository and upload files via GitHub **Add file → Upload files** (browser method), including the `static` and `certificates` folders. Do not upload databases, secrets or company documents. GitHub's web upload has file-count/size limits; GitHub Desktop is an alternative.
3. Render → New → Web Service → connect repository.
4. Build: `pip install -r requirements.txt`
5. Start: `uvicorn app:app --host 0.0.0.0 --port $PORT`
6. Select Free instance if available. Set `GRC_ADMIN_PASSWORD` to a strong secret **only if** you intend to use owner features; don't use owner features with confidential documents on this prototype.
7. Open Render URL `/` and `/workspace`.

**Limits:** Free Render instances can sleep and have ephemeral storage. Uploaded certificates and SQLite changes will not persist reliably. Migrate to persistent storage and upgrade authentication before production use. The ISO keyword matcher is not a compliance audit or certification.
