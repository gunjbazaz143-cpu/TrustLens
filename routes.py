"""
TrustLens - AI Based Information Verification System
routes.py - all application routes (public, auth, user, scanners, admin).

Every scanner POST validates its input, runs a real analysis engine from
utils.py, persists the scan, raises a notification, and redirects to the
evidence-backed result page. Nothing here returns fabricated scores.
"""

import csv
import io
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

from flask import (current_app, flash, redirect, render_template, request,
                   send_file, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from urllib.parse import urlsplit
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from models import (ActivityLog, ContactMessage, Notification, Report,
                    ScanRecord, ScamReport, Setting, UploadedFile, User, db)
from utils import (allowed_file, generate_pdf_report, human_size, allow_request,
                   image_scanner, ingredient_scanner, job_scanner,
                   log_activity, news_scanner, notify, qr_scanner, safe_json,
                   claim_checker, text_scanner, website_scanner)

app = current_app  # module-level handle is replaced below via decorators


def get_app():
    from app import app as _app
    return _app


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

def save_upload(file_storage, subfolder="images"):
    """Persist an upload to disk with a random name. Returns metadata tuple."""
    folder = os.path.join(current_app.config["UPLOAD_FOLDER"], subfolder)
    os.makedirs(folder, exist_ok=True)
    original = file_storage.filename or "upload"
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else "bin"
    stored = "%s.%s" % (uuid.uuid4().hex, ext)
    path = os.path.join(folder, stored)
    file_storage.save(path)
    return {"original": original, "stored": stored, "path": path,
            "size": os.path.getsize(path), "mime": file_storage.mimetype}


def record_upload(user, scan_id, meta):
    db.session.add(UploadedFile(user_id=user.id if user else None, scan_id=scan_id,
                                original_name=meta["original"], stored_name=meta["stored"],
                                size=meta["size"], mime=meta["mime"]))
    db.session.commit()


def save_scan(scan_type, input_summary, result, user):
    rec = ScanRecord(
        user_id=user.id if user else None,
        scan_type=scan_type,
        input_summary=(input_summary or "")[:500],
        trust_score=result.get("score"),
        risk_level=result.get("risk"),
        status=result.get("status", "verified"),
        summary=(result.get("summary") or "")[:1000],
        reasons_json=safe_json(result.get("reasons", [])),
        suggestions_json=safe_json(result.get("suggestions", [])),
        meta_json=safe_json(result.get("meta", {})),
    )
    db.session.add(rec)
    db.session.commit()
    return rec.id


def post_scan_notification(user, scan_type, result):
    if not user:
        return
    s = result.get("score")
    if s is None:
        msg = "%s scan: insufficient evidence to score." % scan_type
    elif s >= 80:
        msg = "%s scan scored %d/100 - low risk." % (scan_type, s)
    elif s >= 50:
        msg = "%s scan scored %d/100 - exercise caution." % (scan_type, s)
    else:
        msg = "%s scan scored %d/100 - high risk." % (scan_type, s)
    notify(user.id, "Verification complete", msg,
           "success" if (s or 100) >= 80 else ("warning" if (s or 100) >= 50 else "danger"))


def scan_client_ip():
    return request.remote_addr


def send_password_reset(email, token):
    """Email the reset link. In dev/no-mail mode, returns the link for display."""
    from flask_mail import Message
    mail = get_app().mail
    link = url_for("reset_password", token=token, _external=True)
    if current_app.config.get("MAIL_USERNAME"):
        try:
            msg = Message("Reset your TrustLens password",
                          recipients=[email])
            msg.body = "Use this link to reset your password (valid 1 hour):\n\n%s" % link
            mail.send(msg)
            return None
        except Exception as exc:
            current_app.logger.error("mail failed: %s", exc)
            return link
    return link


# --------------------------------------------------------------------------- #
#  Decorators
# --------------------------------------------------------------------------- #

def admin_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please sign in as an administrator.", "warning")
            return redirect(url_for("admin_login"))
        if not current_user.is_admin:
            flash("You do not have administrator access.", "danger")
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped


def unauthenticated_only(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


# --------------------------------------------------------------------------- #
#  Public pages
# --------------------------------------------------------------------------- #

def _home_stats():
    total_scans = ScanRecord.query.count()
    total_users = User.query.count()
    total_reports = Report.query.count()
    scored = [r.trust_score for r in ScanRecord.query.filter(ScanRecord.trust_score.isnot(None)).all()]
    avg = (sum(scored) / len(scored)) if scored else None
    return {"total_scans": total_scans, "total_users": total_users,
            "total_reports": total_reports, "avg_score": avg}


def index():
    stats = _home_stats()
    return render_template("index.html", stats=stats)


def about():
    return render_template("about.html")


def features():
    return render_template("features.html")


def faq():
    return render_template("faq.html")


def privacy():
    return render_template("privacy.html")


def terms():
    return render_template("terms.html")


def scanner_index():
    return render_template("scanner_index.html")


def contact():
    if request.method == "POST":
        if not allow_request("contact", current_app.config.get("REGISTER_LIMIT", 4) + 2):
            flash("Too many messages. Please wait a moment.", "warning")
            return redirect(url_for("contact"))
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("contact"))
        if not subject or not message:
            flash("Please fill in the subject and message.", "error")
            return redirect(url_for("contact"))
        db.session.add(ContactMessage(name=name or "Anonymous", email=email,
                                      subject=subject, message=message))
        db.session.commit()
        log_activity("contact_submitted", subject, current_user if current_user.is_authenticated else None)
        notify(current_user.id, "Message sent", "Your message was received. We reply within 2 working days.",
               "success") if current_user.is_authenticated else None
        flash("Your message has been sent successfully.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")


def newsletter():
    email = request.form.get("email", "").strip()
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        db.session.add(ContactMessage(name="Newsletter", email=email,
                                      subject="Newsletter subscription", message="Subscribe"))
        db.session.commit()
        flash("Subscribed to the newsletter. Thank you!", "success")
    else:
        flash("Please enter a valid email address.", "error")
    return redirect(url_for("index"))


def report_scam():
    submitted = None
    if request.method == "POST":
        scam_type = request.form.get("scam_type", "").strip() or "Other"
        subject = request.form.get("subject", "").strip()
        details = request.form.get("details", "").strip()
        url = request.form.get("url", "").strip()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        if subject or details or url:
            db.session.add(ScamReport(name=name or "Anonymous", email=email or None,
                                      scam_type=scam_type, subject=subject or None,
                                      details=details or None, url=url or None))
            db.session.commit()
            submitted = ScamReport.query.order_by(ScamReport.id.desc()).first()
            log_activity("scam_report_submitted", scam_type,
                         current_user if current_user.is_authenticated else None)
        else:
            flash("Please describe the scam or paste the malicious URL.", "error")
    reports = ScamReport.query.order_by(ScamReport.id.desc()).limit(10).all()
    return render_template("report.html", submitted=submitted, reports=reports)


# --------------------------------------------------------------------------- #
#  Authentication
# --------------------------------------------------------------------------- #

@unauthenticated_only
def register():
    if request.method == "POST":
        if not allow_request("register", current_app.config.get("REGISTER_LIMIT", 4)):
            flash("Too many sign-up attempts. Please try again later.", "warning")
            return redirect(url_for("register"))
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(name) < 2:
            flash("Please enter your full name.", "error")
        elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Please enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "error")
        else:
            user = User(name=name, email=email, role="user")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            log_activity("user_registered", email, user)
            notify(user.id, "Welcome to TrustLens",
                   "Your account is ready. Start verifying content today.", "success")
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@unauthenticated_only
def login():
    if request.method == "POST":
        if not allow_request("login", current_app.config.get("LOGIN_LIMIT", 8)):
            flash("Too many login attempts. Please wait a moment.", "warning")
            return redirect(url_for("login"))
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password):
            log_activity("login_failed", email)
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))
        if not user.is_active:
            flash("This account has been suspended. Contact support.", "error")
            return redirect(url_for("login"))
        login_user(user, remember=remember)
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        log_activity("login_success", email, user)
        notify(user.id, "Signed in", "Welcome back, %s!" % user.name, "success")
        nxt = request.args.get("next")
        if nxt and urlsplit(nxt).netloc == "":
            return redirect(nxt)
        return redirect(url_for("dashboard"))
    return render_template("login.html")


def logout():
    if current_user.is_authenticated:
        log_activity("logout", current_user.email, current_user)
        logout_user()
        flash("You have been signed out.", "success")
    return redirect(url_for("index"))


def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
            token = s.dumps(email, salt="password-reset")
            link = send_password_reset(email, token)
            if link:
                flash("Email delivery is not configured (dev mode). Use this reset link: %s" % link, "success")
            else:
                flash("A password reset link has been sent to your email.", "success")
        else:
            flash("If that email exists, a reset link has been sent.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


def reset_password(token):
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        email = s.loads(token, salt="password-reset", max_age=3600)
    except SignatureExpired:
        flash("This reset link has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("This reset link is invalid.", "error")
        return redirect(url_for("forgot_password"))
    user = User.query.filter_by(email=email).first()
    if user is None:
        flash("This account no longer exists.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            user.set_password(password)
            db.session.commit()
            log_activity("password_reset", email, user)
            notify(user.id, "Password changed", "Your password was reset successfully.", "success")
            flash("Your password has been reset. Please sign in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


@login_required
def profile():
    user = current_user
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "update_profile":
            name = request.form.get("name", "").strip()
            if len(name) >= 2:
                user.name = name
                db.session.commit()
                flash("Profile updated.", "success")
            else:
                flash("Name must be at least 2 characters.", "error")
        elif action == "change_password":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not user.check_password(current_pw):
                flash("Current password is incorrect.", "error")
            elif len(new_pw) < 8:
                flash("New password must be at least 8 characters.", "error")
            elif new_pw != confirm:
                flash("New passwords do not match.", "error")
            else:
                user.set_password(new_pw)
                db.session.commit()
                log_activity("profile_password_changed", "", user)
                notify(user.id, "Password changed", "Your password was updated.", "success")
                flash("Password updated successfully.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


# --------------------------------------------------------------------------- #
#  User dashboard / history / reports
# --------------------------------------------------------------------------- #

def _dashboard_series(days=14):
    start = datetime.now(timezone.utc) - timedelta(days=days - 1)
    rows = ScanRecord.query.filter(ScanRecord.created_at >= start).all()
    by_day = {}
    for r in rows:
        key = r.created_at.strftime("%Y-%m-%d")
        by_day[key] = by_day.get(key, 0) + 1
    labels, values = [], []
    for i in range(days):
        d = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        labels.append(d)
        values.append(by_day.get(d, 0))
    return labels, values


def _dashboard_stats():
    scans = ScanRecord.query
    risk_dist = {"low": 0, "medium": 0, "high": 0, "unknown": 0}
    for r in ScanRecord.query.filter(ScanRecord.risk_level.isnot(None)).all():
        risk_dist[r.risk_level] = risk_dist.get(r.risk_level, 0) + 1
    cat_dist = {}
    for r in ScanRecord.query.all():
        cat_dist[r.scan_type] = cat_dist.get(r.scan_type, 0) + 1
    labels, daily = _dashboard_series()
    return {"risk_dist": risk_dist, "cat_dist": cat_dist,
            "chart_labels": labels, "chart_daily": daily}


@login_required
def dashboard():
    stats = _home_stats()
    mine = ScanRecord.query.filter_by(user_id=current_user.id)
    recent = mine.order_by(ScanRecord.id.desc()).limit(6).all()
    unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    charts = _dashboard_stats()
    return render_template("dashboard.html", stats=stats, recent=recent,
                           unread=unread, charts=charts)


@login_required
def history():
    q = ScanRecord.query.filter_by(user_id=current_user.id)
    scan_type = request.args.get("type", "").strip()
    risk = request.args.get("risk", "").strip()
    search = request.args.get("q", "").strip()
    if scan_type:
        q = q.filter(ScanRecord.scan_type == scan_type)
    if risk:
        q = q.filter(ScanRecord.risk_level == risk)
    if search:
        q = q.filter(ScanRecord.input_summary.contains(search) |
                     ScanRecord.summary.contains(search))
    page = request.args.get("page", 1, type=int)
    pagination = q.order_by(ScanRecord.id.desc()).paginate(page=page, per_page=10)
    scan_types = [t[0] for t in db.session.query(ScanRecord.scan_type).distinct().all()]
    return render_template("history.html", pagination=pagination,
                           scan_types=scan_types, filters={"type": scan_type,
                                                           "risk": risk, "q": search})


@login_required
def delete_scan(scan_id):
    rec = ScanRecord.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(rec)
    db.session.commit()
    flash("Scan deleted from history.", "success")
    return redirect(url_for("history"))


def view_result(scan_id):
    rec = ScanRecord.query.get_or_404(scan_id)
    if rec.user_id and (not current_user.is_authenticated or rec.user_id != current_user.id):
        flash("You do not have access to that scan.", "error")
        return redirect(url_for("index"))
    data = rec.as_dict()
    data["id"] = rec.id
    owner = (rec.user_id is not None and current_user.is_authenticated
             and rec.user_id == current_user.id)
    recent_news = None
    if rec.scan_type == "News":
        q = ScanRecord.query.filter_by(scan_type="News")
        if rec.user_id:
            q = q.filter_by(user_id=rec.user_id)
        else:
            q = q.filter_by(user_id=None)
        rows = q.order_by(ScanRecord.id.desc()).limit(6).all()
        recent_news = []
        for r in rows:
            if r.id == rec.id:
                continue
            m = r.as_dict()
            recent_news.append({"id": r.id,
                                "verdict": m.get("meta", {}).get("verdict", ""),
                                "verdict_label": m.get("meta", {}).get("verdict_label", ""),
                                "confidence": m.get("meta", {}).get("confidence"),
                                "summary": (m.get("meta", {}).get("main_claim") or r.input_summary or "")[:110],
                                "created_at": r.created_at})
        recent_news = recent_news[:5]
    return render_template("result.html", data=data, user=current_user, owner=owner,
                           recent_news=recent_news)


@login_required
def generate_report(scan_id):
    rec = ScanRecord.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    data = rec.as_dict()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = "trustlens_scan_%d_%s.pdf" % (rec.id, stamp)
    path = os.path.join(current_app.config["REPORT_FOLDER"], filename)
    ok = generate_pdf_report(data, current_user.name, path)
    if not ok:
        flash("PDF generation failed (reportlab unavailable).", "error")
        return redirect(url_for("history"))
    db.session.add(Report(user_id=current_user.id, scan_id=rec.id,
                          filename=filename, filepath=path))
    rec.is_saved_report = True
    db.session.commit()
    notify(current_user.id, "Report generated", "PDF report for scan #%d is ready." % rec.id, "success")
    log_activity("report_generated", filename, current_user)
    flash("PDF report generated successfully.", "success")
    return redirect(url_for("reports"))


@login_required
def reports():
    rows = Report.query.filter_by(user_id=current_user.id).order_by(Report.id.desc()).all()
    return render_template("reports.html", reports=rows)


@login_required
def download_report(report_id):
    row = Report.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    if not os.path.exists(row.filepath):
        flash("The report file no longer exists.", "error")
        return redirect(url_for("reports"))
    log_activity("report_downloaded", row.filename, current_user)
    return send_file(row.filepath, as_attachment=True, download_name=row.filename)


@login_required
def delete_report(report_id):
    row = Report.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    try:
        if os.path.exists(row.filepath):
            os.remove(row.filepath)
    except OSError:
        pass
    db.session.delete(row)
    db.session.commit()
    flash("Report deleted.", "success")
    return redirect(url_for("reports"))


# --------------------------------------------------------------------------- #
#  Scanners
# --------------------------------------------------------------------------- #

def _process(upload_field, scan_type, input_summary, run, allowed_exts):
    """Shared scanner POST handler: validate, run, persist, notify, redirect."""
    if not allow_request("scan", current_app.config.get("SCAN_LIMIT", 20)):
        flash("Scan limit reached. Please wait a moment.", "warning")
        return redirect(url_for("scanner_index"))
    f = request.files.get(upload_field)
    upload_meta = None
    if f and f.filename:
        if not allowed_file(f.filename, allowed_exts):
            flash("Unsupported file type.", "error")
            return redirect(url_for("scanner_index"))
        upload_meta = save_upload(f)
    result = run(upload_meta)
    user = current_user if current_user.is_authenticated else None
    scan_id = save_scan(scan_type, input_summary, result, user)
    if upload_meta:
        record_upload(user, scan_id, upload_meta)
    post_scan_notification(user, scan_type, result)
    log_activity("scan_completed", "%s -> %s" % (scan_type, result.get("status")), user)
    return redirect(url_for("view_result", scan_id=scan_id))


def scanner_text():
    if request.method == "POST":
        text = request.form.get("text", "")
        if not text.strip():
            flash("Please paste some content to verify.", "error")
            return redirect(url_for("scanner_text"))
        return _process("file", "Text / Email", text[:150], lambda m: text_scanner(text),
                        current_app.config["ALLOWED_IMAGE_EXTENSIONS"])
    return render_template("scanner_text.html")


def scanner_image():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please upload an image to verify.", "error")
            return redirect(url_for("scanner_image"))
        if not allowed_file(f.filename, current_app.config["ALLOWED_IMAGE_EXTENSIONS"]):
            flash("Unsupported image type.", "error")
            return redirect(url_for("scanner_image"))
        meta = save_upload(f, "images")
        result = image_scanner(meta["path"], meta["original"])
        return _finish_image_scan(meta, result)
    return render_template("scanner_image.html")


def _finish_image_scan(meta, result, scan_type="Image / QR / Reverse", label="Image"):
    user = current_user if current_user.is_authenticated else None
    scan_id = save_scan(scan_type, meta["original"], result, user)
    record_upload(user, scan_id, meta)
    post_scan_notification(user, label, result)
    return redirect(url_for("view_result", scan_id=scan_id))


def scanner_website():
    if request.method == "POST":
        url = request.form.get("url", "")
        if not url.strip():
            flash("Please enter a website URL.", "error")
            return redirect(url_for("scanner_website"))
        return _process("file", "Website", url[:150], lambda m: website_scanner(url),
                        current_app.config["ALLOWED_IMAGE_EXTENSIONS"])
    return render_template("scanner_website.html")


def scanner_news():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        headline = request.form.get("headline", "").strip()
        text = request.form.get("text", "").strip()
        f = request.files.get("file")
        if not (url or headline or text or (f and f.filename)):
            flash("Provide a news URL, headline, article text or screenshot.", "error")
            return redirect(url_for("scanner_news"))
        upload_meta = None
        if f and f.filename:
            if not allowed_file(f.filename, current_app.config["ALLOWED_FILE_EXTENSIONS"]):
                flash("Screenshots must be an image and documents must be a PDF.", "error")
                return redirect(url_for("scanner_news"))
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            subfolder = "documents" if ext == "pdf" else "images"
            upload_meta = save_upload(f, subfolder)
        result = news_scanner(url=url, headline=headline, text=text,
                              file_path=upload_meta["path"] if upload_meta else None,
                              file_name=upload_meta["original"] if upload_meta else "")
        user = current_user if current_user.is_authenticated else None
        scan_id = save_scan("News", (headline or url or text)[:150], result, user)
        if upload_meta:
            record_upload(user, scan_id, upload_meta)
        post_scan_notification(user, "News", result)
        return redirect(url_for("view_result", scan_id=scan_id))
    return render_template("scanner_news.html")


def scanner_job():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        text = request.form.get("text", "").strip()
        f = request.files.get("file")
        if not (url or text or (f and f.filename)):
            flash("Provide a job URL, the posting text, or an offer letter file.", "error")
            return redirect(url_for("scanner_job"))
        upload_meta = None
        if f and f.filename:
            if not allowed_file(f.filename, current_app.config["ALLOWED_FILE_EXTENSIONS"]):
                flash("Offer letters must be a PDF or image.", "error")
                return redirect(url_for("scanner_job"))
            upload_meta = save_upload(f, "documents")
        result = job_scanner(url=url, text=text,
                             file_path=upload_meta["path"] if upload_meta else None,
                             file_name=upload_meta["original"] if upload_meta else "")
        user = current_user if current_user.is_authenticated else None
        scan_id = save_scan("Job / Internship", (url or text or (upload_meta or {}).get("original", ""))[:150],
                            result, user)
        if upload_meta:
            record_upload(user, scan_id, upload_meta)
        post_scan_notification(user, "Job", result)
        return redirect(url_for("view_result", scan_id=scan_id))
    return render_template("scanner_job.html")


def scanner_claim():
    if request.method == "POST":
        claim = request.form.get("claim", "")
        if len(claim.strip()) < 8:
            flash("Please enter a complete claim statement.", "error")
            return redirect(url_for("scanner_claim"))
        return _process("file", "Claim", claim[:150], lambda m: claim_checker(claim),
                        current_app.config["ALLOWED_IMAGE_EXTENSIONS"])
    return render_template("scanner_claim.html")


def scanner_ingredient():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please upload a photo of the product's back label.", "error")
            return redirect(url_for("scanner_ingredient"))
        if not allowed_file(f.filename, current_app.config["ALLOWED_IMAGE_EXTENSIONS"]):
            flash("Unsupported image type.", "error")
            return redirect(url_for("scanner_ingredient"))
        meta = save_upload(f, "labels")
        result = ingredient_scanner(meta["path"], meta["original"])
        return _finish_image_scan(meta, result, "Ingredients", "Ingredients")
    return render_template("scanner_ingredient.html")


def scanner_qr():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please upload an image containing a QR code.", "error")
            return redirect(url_for("scanner_qr"))
        if not allowed_file(f.filename, current_app.config["ALLOWED_IMAGE_EXTENSIONS"]):
            flash("Unsupported image type.", "error")
            return redirect(url_for("scanner_qr"))
        meta = save_upload(f, "qr")
        result = qr_scanner(meta["path"])
        return _finish_image_scan(meta, result, "QR", "QR")
    return render_template("scanner_qr.html")


# --------------------------------------------------------------------------- #
#  Admin
# --------------------------------------------------------------------------- #

def admin_login():
    if request.method == "POST":
        if not allow_request("login", current_app.config.get("LOGIN_LIMIT", 8)):
            flash("Too many attempts. Please wait.", "warning")
            return redirect(url_for("admin_login"))
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password) or not user.is_admin:
            log_activity("admin_login_failed", email)
            flash("Invalid admin credentials.", "error")
            return redirect(url_for("admin_login"))
        if not user.is_active:
            flash("This admin account is suspended.", "error")
            return redirect(url_for("admin_login"))
        login_user(user, remember=False)
        log_activity("admin_login", email, user)
        return redirect(url_for("admin_dashboard"))
    return render_template("admin/admin_login.html")


@admin_required
def admin_dashboard():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_scans = ScanRecord.query.count()
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_scans = ScanRecord.query.filter(ScanRecord.created_at >= today_start).count()
    total_reports = Report.query.count()
    unread_messages = ContactMessage.query.filter_by(is_read=False).count()
    charts = _dashboard_stats()
    recent_scans = ScanRecord.query.order_by(ScanRecord.id.desc()).limit(8).all()
    recent_users = User.query.order_by(User.id.desc()).limit(6).all()
    return render_template("admin/admin_dashboard.html",
                           totals={"users": total_users, "active": active_users,
                                   "scans": total_scans, "today": today_scans,
                                   "reports": total_reports, "unread": unread_messages},
                           charts=charts, recent_scans=recent_scans, recent_users=recent_users)


@admin_required
def admin_users():
    search = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    q = User.query
    if search:
        q = q.filter(db.or_(User.name.contains(search), User.email.contains(search)))
    if status == "active":
        q = q.filter_by(is_active=True)
    elif status == "suspended":
        q = q.filter_by(is_active=False)
    users = q.order_by(User.id.desc()).all()
    return render_template("admin/admin_users.html", users=users, q=search, status=status)


@admin_required
def admin_user_action(user_id, action):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot modify your own admin account here.", "error")
        return redirect(url_for("admin_users"))
    if action == "suspend":
        user.is_active = False
        db.session.commit()
        log_activity("user_suspended", user.email, current_user)
        flash("User suspended.", "success")
    elif action == "unsuspend":
        user.is_active = True
        db.session.commit()
        log_activity("user_unsuspended", user.email, current_user)
        flash("User restored.", "success")
    elif action == "delete":
        db.session.delete(user)
        db.session.commit()
        log_activity("user_deleted", user.email, current_user)
        flash("User and their records deleted.", "success")
    return redirect(url_for("admin_users"))


@admin_required
def admin_scans():
    scan_type = request.args.get("type", "").strip()
    risk = request.args.get("risk", "").strip()
    q = ScanRecord.query
    if scan_type:
        q = q.filter_by(scan_type=scan_type)
    if risk:
        q = q.filter_by(risk_level=risk)
    scans = q.order_by(ScanRecord.id.desc()).limit(200).all()
    return render_template("admin/admin_scans.html", scans=scans)


@admin_required
def admin_delete_scan(scan_id):
    rec = ScanRecord.query.get_or_404(scan_id)
    db.session.delete(rec)
    db.session.commit()
    log_activity("admin_scan_deleted", "#%d" % scan_id, current_user)
    flash("Scan deleted.", "success")
    return redirect(url_for("admin_scans"))


@admin_required
def admin_reports():
    reports = Report.query.order_by(Report.id.desc()).all()
    return render_template("admin/admin_reports.html", reports=reports)


@admin_required
def admin_delete_report(report_id):
    row = Report.query.get_or_404(report_id)
    try:
        if os.path.exists(row.filepath):
            os.remove(row.filepath)
    except OSError:
        pass
    db.session.delete(row)
    db.session.commit()
    log_activity("admin_report_deleted", row.filename, current_user)
    flash("Report deleted.", "success")
    return redirect(url_for("admin_reports"))


@admin_required
def admin_export_reports():
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "User", "Scan", "Filename", "Created"])
    for r in Report.query.order_by(Report.id.desc()).all():
        u = User.query.get(r.user_id) if r.user_id else None
        writer.writerow([r.id, u.email if u else "", r.scan_id, r.filename,
                         r.created_at.strftime("%Y-%m-%d %H:%M")])
    buf.seek(0)
    return send_file(io.BytesIO(buf.getvalue().encode("utf-8-sig")),
                     as_attachment=True, download_name="trustlens_reports.csv",
                     mimetype="text/csv")


@admin_required
def admin_messages():
    messages = ContactMessage.query.order_by(ContactMessage.id.desc()).all()
    return render_template("admin/admin_messages.html", messages=messages)


@admin_required
def admin_message_action(message_id, action):
    msg = ContactMessage.query.get_or_404(message_id)
    if action == "read":
        msg.is_read = True
    elif action == "delete":
        db.session.delete(msg)
    db.session.commit()
    return redirect(url_for("admin_messages"))


@admin_required
def admin_logs():
    logs = ActivityLog.query.order_by(ActivityLog.id.desc()).limit(200).all()
    return render_template("admin/admin_logs.html", logs=logs)


@admin_required
def admin_settings():
    if request.method == "POST":
        Setting.set("site_name", request.form.get("site_name", "TrustLens"))
        Setting.set("maintenance_mode", request.form.get("maintenance_mode", "off"))
        Setting.set("max_upload_mb", request.form.get("max_upload_mb", "16"))
        log_activity("settings_updated", "", current_user)
        flash("Settings saved.", "success")
        return redirect(url_for("admin_settings"))
    return render_template("admin/admin_settings.html",
                           settings={s.key: s.value for s in Setting.query.all()})


# --------------------------------------------------------------------------- #
#  Route registration (kept flat per project structure)
# --------------------------------------------------------------------------- #

def register_routes(app_):
    global app
    app = app_

    app.add_url_rule("/", "index", index)
    app.add_url_rule("/about", "about", about)
    app.add_url_rule("/features", "features", features)
    app.add_url_rule("/faq", "faq", faq)
    app.add_url_rule("/privacy", "privacy", privacy)
    app.add_url_rule("/terms", "terms", terms)
    app.add_url_rule("/scanner", "scanner_index", scanner_index)
    app.add_url_rule("/contact", "contact", contact, methods=["GET", "POST"])
    app.add_url_rule("/newsletter", "newsletter", newsletter, methods=["POST"])
    app.add_url_rule("/report", "report_scam", report_scam, methods=["GET", "POST"])

    app.add_url_rule("/register", "register", register, methods=["GET", "POST"])
    app.add_url_rule("/login", "login", login, methods=["GET", "POST"])
    app.add_url_rule("/logout", "logout", logout, methods=["POST"])
    app.add_url_rule("/forgot-password", "forgot_password", forgot_password, methods=["GET", "POST"])
    app.add_url_rule("/reset-password/<token>", "reset_password", reset_password, methods=["GET", "POST"])
    app.add_url_rule("/profile", "profile", profile, methods=["GET", "POST"])

    app.add_url_rule("/dashboard", "dashboard", dashboard)
    app.add_url_rule("/history", "history", history)
    app.add_url_rule("/history/delete/<int:scan_id>", "delete_scan", delete_scan, methods=["POST"])
    app.add_url_rule("/scan/<int:scan_id>", "view_result", view_result)
    app.add_url_rule("/scan/<int:scan_id>/report", "generate_report", generate_report, methods=["POST"])
    app.add_url_rule("/reports", "reports", reports)
    app.add_url_rule("/reports/<int:report_id>/download", "download_report", download_report)
    app.add_url_rule("/reports/<int:report_id>/delete", "delete_report", delete_report, methods=["POST"])

    app.add_url_rule("/scanner/text", "scanner_text", scanner_text, methods=["GET", "POST"])
    app.add_url_rule("/scanner/image", "scanner_image", scanner_image, methods=["GET", "POST"])
    app.add_url_rule("/scanner/website", "scanner_website", scanner_website, methods=["GET", "POST"])
    app.add_url_rule("/scanner/news", "scanner_news", scanner_news, methods=["GET", "POST"])
    app.add_url_rule("/scanner/job", "scanner_job", scanner_job, methods=["GET", "POST"])
    app.add_url_rule("/scanner/claim", "scanner_claim", scanner_claim, methods=["GET", "POST"])
    app.add_url_rule("/scanner/ingredient", "scanner_ingredient", scanner_ingredient, methods=["GET", "POST"])
    app.add_url_rule("/scanner/qr", "scanner_qr", scanner_qr, methods=["GET", "POST"])

    app.add_url_rule("/admin/login", "admin_login", admin_login, methods=["GET", "POST"])
    app.add_url_rule("/admin", "admin_dashboard", admin_dashboard)
    app.add_url_rule("/admin/users", "admin_users", admin_users)
    app.add_url_rule("/admin/users/<int:user_id>/<action>", "admin_user_action", admin_user_action, methods=["POST"])
    app.add_url_rule("/admin/scans", "admin_scans", admin_scans)
    app.add_url_rule("/admin/scans/<int:scan_id>/delete", "admin_delete_scan", admin_delete_scan, methods=["POST"])
    app.add_url_rule("/admin/reports", "admin_reports", admin_reports)
    app.add_url_rule("/admin/reports/<int:report_id>/delete", "admin_delete_report", admin_delete_report, methods=["POST"])
    app.add_url_rule("/admin/reports/export", "admin_export_reports", admin_export_reports)
    app.add_url_rule("/admin/messages", "admin_messages", admin_messages)
    app.add_url_rule("/admin/messages/<int:message_id>/<action>", "admin_message_action", admin_message_action, methods=["POST"])
    app.add_url_rule("/admin/logs", "admin_logs", admin_logs)
    app.add_url_rule("/admin/settings", "admin_settings", admin_settings, methods=["GET", "POST"])
