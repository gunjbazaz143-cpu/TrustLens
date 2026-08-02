"""
TrustLens - AI Based Information Verification System
Database models (SQLAlchemy + SQLite).

Tables: User (users + admins via role), UploadedFile, ScanRecord (history),
TrustScore is embedded on ScanRecord, Report (generated PDFs), Notification,
ContactMessage, ScamReport (community registry), ActivityLog, Setting,
KnowledgeItem (claim-checker evidence base).

All tables use proper relationships, indexes and timestamps.
"""

from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
#  Identity
# --------------------------------------------------------------------------- #

class User(UserMixin, db.Model):
    """A registered user. Admins are users with role='admin' (RBAC)."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # user | admin
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    scans = db.relationship("ScanRecord", backref="user", lazy="dynamic")
    notifications = db.relationship("Notification", backref="user", lazy="dynamic")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return "<User %s (%s)>" % (self.email, self.role)


# --------------------------------------------------------------------------- #
#  Scans & files
# --------------------------------------------------------------------------- #

class ScanRecord(db.Model):
    """A single verification run. Holds the computed trust score and the full
    evidence-backed explanation produced by the analysis engine."""

    __tablename__ = "scan_records"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    scan_type = db.Column(db.String(40), nullable=False, index=True)
    input_summary = db.Column(db.Text, nullable=True)

    # None means "Insufficient Evidence" - never a fabricated number.
    trust_score = db.Column(db.Integer, nullable=True, index=True)
    risk_level = db.Column(db.String(20), nullable=True, index=True)
    status = db.Column(db.String(20), nullable=False, default="verified")  # verified | insufficient | error
    summary = db.Column(db.Text, nullable=True)

    reasons_json = db.Column(db.Text, nullable=True)   # JSON list of evidence entries
    suggestions_json = db.Column(db.Text, nullable=True)
    meta_json = db.Column(db.Text, nullable=True)

    is_saved_report = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    files = db.relationship("UploadedFile", backref="scan", lazy="dynamic")
    reports = db.relationship("Report", backref="scan", lazy="dynamic")

    def as_dict(self):
        import json as _json
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "input_summary": self.input_summary,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "status": self.status,
            "summary": self.summary,
            "reasons": _json.loads(self.reasons_json) if self.reasons_json else [],
            "suggestions": _json.loads(self.suggestions_json) if self.suggestions_json else [],
            "meta": _json.loads(self.meta_json) if self.meta_json else {},
            "created_at": self.created_at,
        }


class UploadedFile(db.Model):
    """Metadata for every file uploaded for analysis. Files are stored on disk
    under uploads/ with a random name; originals are never exposed."""

    __tablename__ = "uploaded_files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_records.id"), nullable=True, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False, index=True)
    size = db.Column(db.Integer, nullable=False)
    mime = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Report(db.Model):
    """Generated PDF report files, linked to a scan."""

    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_records.id"), nullable=True, index=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


# --------------------------------------------------------------------------- #
#  Communication
# --------------------------------------------------------------------------- #

class Notification(db.Model):
    """User-facing notifications for important actions."""

    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    title = db.Column(db.String(160), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(20), nullable=False, default="info")  # success|warning|danger|info
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class ContactMessage(db.Model):
    """Messages submitted through the contact form / newsletter."""

    __tablename__ = "contact_messages"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, default="Anonymous")
    email = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class ScamReport(db.Model):
    """Community-contributed scam pattern reports shown on the Report page."""

    __tablename__ = "scam_reports"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, default="Anonymous")
    email = db.Column(db.String(255), nullable=True)
    scam_type = db.Column(db.String(80), nullable=False)
    subject = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(500), nullable=True)
    submitted_at = db.Column(db.DateTime, nullable=False, default=utcnow)


# --------------------------------------------------------------------------- #
#  Ops
# --------------------------------------------------------------------------- #

class ActivityLog(db.Model):
    """Audit trail for admin operations."""

    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True, index=True)
    username = db.Column(db.String(120), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Setting(db.Model):
    """Key/value system settings editable from the admin panel."""

    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)

    @staticmethod
    def get(key, default=None):
        row = Setting.query.filter_by(key=key).first()
        return row.value if row else default

    @staticmethod
    def set(key, value):
        row = Setting.query.filter_by(key=key).first()
        if row is None:
            row = Setting(key=key)
            db.session.add(row)
        row.value = value
        db.session.commit()


# --------------------------------------------------------------------------- #
#  Knowledge base (claim checker evidence)
# --------------------------------------------------------------------------- #

class KnowledgeItem(db.Model):
    """Verified claims used by the claim checker and news cross-checker."""

    __tablename__ = "knowledge_items"

    id = db.Column(db.Integer, primary_key=True)
    claim = db.Column(db.Text, nullable=False)
    verdict = db.Column(db.String(10), nullable=False)   # true | false
    category = db.Column(db.String(60), nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    source = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
