# TrustLens — AI Based Information Verification System

A production-grade Flask application that verifies the trustworthiness of
text, images, websites, news, job offers, claims, product labels and QR codes.
Every score is computed from **real evidence** extracted from the input. When
there is not enough evidence, the app honestly reports **"Insufficient Evidence"**
instead of inventing a number.

## Key principles

- **No fabricated scores.** Scores are derived from OCR output, image metrics,
  link inspection, network responses, similarity against documented scam
  patterns and a seeded knowledge base.
- **Insufficient evidence is a first-class outcome.** Short/empty inputs,
  failed OCR, unreachable sites or unmatched claims return `status=insufficient`
  with a `None` score and helpful guidance.
- **Graceful degradation.** Optional dependencies (EasyOCR, scikit-learn, live
  network, PDF parsing) degrade to explanatory messages rather than crashes.

## Features

- 9 scanners: Text / Email, Image (payment screenshots, reverse-image), Website,
  News, Job / Internship, Claim checker, Product ingredients, QR code.
- User accounts with signup, login, password reset, profile management.
- Per-user dashboard, scan history with filters, saved reports.
- Professional **PDF reports** (ReportLab) for every saved scan.
- Admin panel: user management (search / suspend / delete), scan overview,
  report management + CSV export, contact messages, audit logs, system settings.
- Community scam report page with public listing.
- Rate limiting per IP, RBAC admin role, password hashing (Werkzeug),
  audit logging on security events.
- Dark / light glassmorphism UI (Bootstrap 5 + Chart.js).

## Project structure

```
TrustLens-Full/
├── app.py          # application factory, seeding, error handlers
├── config.py       # configuration (env-overridable)
├── models.py       # SQLAlchemy models
├── routes.py       # all routes (public, auth, user, scanners, admin)
├── utils.py        # analysis engines, scoring, PDF, rate limiting
├── requirements.txt
├── README.md
├── database/       # (reserved) SQLite can live here
├── instance/       # trustlens.db is created here automatically
├── uploads/        # user uploads (images, qr, documents, labels)
├── reports/        # generated PDF reports
├── templates/      # Jinja2 templates (incl. admin/)
└── static/         # css/, js/, images/, icons/
```

## Quick start

```bash
pip install -r requirements.txt

# optional: point EasyOCR / network checks off for a fully offline run
# set TRUSTLENS_ENABLE_OCR=0 and TRUSTLENS_LIVE_NETWORK=0 if needed

python app.py
# default port 5000; if busy, use:
# TRUSTLENS_PORT=5001 python app.py
```

Open http://localhost:5001 (or your port).

- **Admin account (change on first login):** `admin@trustlens.app` / `Admin@123456`
- Regular users can self-register on `/register`.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | dev default | Sessions / tokens (set in production) |
| `TRUSTLENS_PORT` / `PORT` | 5000 | HTTP port |
| `FLASK_DEBUG` | 0 | Debug mode |
| `TRUSTLENS_ENABLE_OCR` | 1 | EasyOCR on/off |
| `TRUSTLENS_LIVE_NETWORK` | 1 | WHOIS / live page / RSS checks |
| `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD` | empty | SMTP for password reset; if empty, reset links are shown on screen in dev mode |

## Security notes

- Passwords are hashed with Werkzeug (`generate_password_hash`).
- Uploads are stored with random names under `uploads/`; originals are never
  exposed via static serving.
- Rate limiting is in-memory per IP and resets on restart.
- The default admin password and dev `SECRET_KEY` **must** be changed before
  any real deployment.

## Disclaimer

TrustLens performs heuristic screening. A high score does not prove content is
safe, and a low score is not a legal verdict. Always verify through official
channels. See the in-app Terms and Privacy pages.
