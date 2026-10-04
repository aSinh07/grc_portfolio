# Aman GRC Nexus V4 — Portfolio + Owner Studio + GRC Lab

## Run locally (Python 3.11+)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
# PowerShell: $env:GRC_ADMIN_PASSWORD="choose-a-long-unique-password"
# macOS/Linux: export GRC_ADMIN_PASSWORD="choose-a-long-unique-password"
python -m uvicorn app:app --reload
```

- Public portfolio: http://127.0.0.1:8000/
- Owner certificate studio: http://127.0.0.1:8000/owner
- Private GRC Lab: http://127.0.0.1:8000/workspace
- Owner HTTP Basic username: `aman`; password: `GRC_ADMIN_PASSWORD` environment variable. **Do not commit your password.**

## What is included

- Mouse sparkles, gradient lighting, responsive animated cards, draggable and zoomable 3D wireframe governance globe, and accessible reduced-motion support.
- Owner-only certificate uploads. New entries persist in SQLite and appear on the public landing page automatically. Two newly supplied credentials are preloaded: Red Team Leaders CLLMSP and ThinkCloudly IT Auditing & GRC.
- Owner-only evidence uploads, editable risk register, charts, 5×5 matrix, and screening across ISO/IEC 42001, ISO/IEC 27001, and NIST AI RMF 1.0.
- Owner-only public webpage text screening, with non-public IP checks and redirect blocking. **This is not an application vulnerability scan or ISO certification.**
- Source code in `app.py`, `static/portfolio.html`, `static/index.html`, `static/owner.html`.

## Free hosting

**Free public portfolio:** GitHub Pages or Cloudflare Pages can host static HTML/CSS/JS, but cannot run this FastAPI/SQLite backend. To publish a static version, update asset paths and remove API-only actions, or deploy the public UI as a static frontend and host the API separately. **Do not put the database, uploads, passwords, or private assessment reports into a public GitHub repository.**

**Dynamic application:** requires a Python hosting service with persistent storage, HTTPS, authentication, and a database. Free tiers vary and may sleep, restrict outbound traffic, or provide ephemeral storage. SQLite data will be lost if hosted on an ephemeral filesystem. Do not deploy private GRC data until proper authentication, authorization, rate limiting, CSRF protection, file scanning, logging, TLS, and hardened URL fetching are implemented. HTTP Basic is only an owner-only local development gate, not a production identity solution. URL fetching has a DNS rebinding / TOCTOU limitation; disable it on untrusted public deployments or isolate outbound traffic.

## Assessment limitations

Keyword matching is **evidence discovery only**. A high match score is NOT proof of implementation, operating effectiveness, ISO 42001 or 27001 compliance, or NIST AI RMF maturity. No official normative ISO text is embedded. Licensed ISO publications and qualified auditor review are required for clause-by-clause assurance. URL reviews inspect only public HTML text, not authentication, application internals, cloud configuration, or a live vulnerability scan. Uploaded scanned PDFs need OCR/manual review.

## Confidentiality

The distribution excludes internal Eigen Secure assessment reports and original risk spreadsheets. Never publish company confidential files or unredacted client evidence.
