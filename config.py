"""
TrustLens - AI Based Information Verification System
Application configuration.

All values can be overridden via environment variables. Sensitive values are
never hardcoded for production use.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    """Base configuration shared by all environments."""

    # --- Core -----------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "trustlens-prod-change-me")
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
    TESTING = os.environ.get("FLASK_TESTING", "0") == "1"
    PORT = int(os.environ.get("TRUSTLENS_PORT") or os.environ.get("PORT") or "5000")

    # --- Database -------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "instance", "trustlens.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Uploads --------------------------------------------------------
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tiff"}
    ALLOWED_PDF_EXTENSIONS = {"pdf"}
    ALLOWED_FILE_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_PDF_EXTENSIONS

    # --- Generated reports ------------------------------------------------
    REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

    # --- Mail (leave empty to run in dev / no-mail mode) ------------------
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "1") == "1"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "TrustLens <noreply@trustlens.app>")

    # --- Behavioural switches ----------------------------------------------
    # EasyOCR downloads its model (~64 MB) on first use. Set to "0" to disable
    # OCR entirely; the image scanner will then report extraction as unavailable
    # instead of fabricating results.
    ENABLE_OCR = os.environ.get("TRUSTLENS_ENABLE_OCR", "1") == "1"
    OCR_LANGUAGES = ["en"]

    # Live network verification (website/news/claim cross-checking). Set to
    # "0" to force offline mode; scanners then return "live verification
    # unavailable" instead of guessing.
    LIVE_NETWORK = os.environ.get("TRUSTLENS_LIVE_NETWORK", "1") == "1"

    # Trusted news feeds used by the news scanner for cross-checking. Each entry
    # names the outlet and its RSS feed; matching reports keep the outlet name
    # and publication date so evidence is traceable. Outlets without a public
    # RSS feed (Reuters, AP, PIB...) are still covered by the trusted-domain
    # allowlist used for live web search below.
    TRUSTED_NEWS_FEEDS = [
        {"name": "BBC News", "url": "https://feeds.bbci.co.uk/news/world/rss.xml"},
        {"name": "The Guardian", "url": "https://www.theguardian.com/world/rss"},
        {"name": "Al Jazeera", "url": "https://www.aljazeera.com/xml/rss/all.xml"},
        {"name": "BBC Technology", "url": "https://feeds.bbci.co.uk/news/technology/rss.xml"},
        {"name": "The Hindu", "url": "https://www.thehindu.com/news/national/feeder/default.rss"},
        {"name": "Indian Express", "url": "https://indianexpress.com/feed/"},
        {"name": "Times of India", "url": "https://timesofindia.indiatimes.com/rssfeeds/-2128936835.cms"},
        {"name": "NDTV", "url": "https://feeds.feedburner.com/ndtvnews-top-stories"},
        {"name": "World Health Organization", "url": "https://www.who.int/rss-feeds/news-english.xml"},
        {"name": "UN News", "url": "https://news.un.org/feed/subscribe/en/news/all/rss.xml"},
    ]

    # News scanner settings --------------------------------------------------
    # Domain allowlist for live web search evidence. Search hits are only kept
    # when their hostname ends with one of these suffixes, so evidence always
    # comes from reputable outlets - never random blogs or aggregators.
    TRUSTED_NEWS_DOMAINS = [
        "reuters.com", "apnews.com", "ap.org", "bbc.co.uk", "bbc.com", "bbc.in",
        "theguardian.com", "aljazeera.com", "thehindu.com", "indianexpress.com",
        "timesofindia.indiatimes.com", "timesofindia.com", "ndtv.com",
        "pib.gov.in", "who.int", "un.org", "news.un.org", "hindustantimes.com",
        "economictimes.indiatimes.com", "mint.com", "moneycontrol.com",
        "ptinews.com", "ians.in", "aninews.in", "gov.in", "nic.in",
        "theweek.in", "frontline.thehindu.com", "dw.com", "france24.com",
    ]

    # Optional Google-style search API key (SerpAPI). When empty the news
    # scanner uses keyless DuckDuckGo / Bing HTML search with the allowlist
    # above, so live verification always works without an API key.
    NEWS_SEARCH_API_KEY = os.environ.get("TRUSTLENS_SEARCH_API_KEY", "")
    NEWS_SEARCH_API_ENGINE = os.environ.get("TRUSTLENS_SEARCH_ENGINE", "serpapi")

    # In-memory cache TTL (seconds) for fetched articles and search results,
    # keeping repeated scans fast without staleness.
    NEWS_CACHE_TTL = int(os.environ.get("TRUSTLENS_NEWS_CACHE_TTL", "3600"))

    # Optional third-party reputation API keys for the QR / website verifier.
    # Leave empty to report those checks as "skipped - key not configured"
    # instead of fabricating a reputation verdict.
    VIRUSTOTAL_KEY = os.environ.get("TRUSTLENS_VIRUSTOTAL_KEY", "")
    SAFE_BROWSING_KEY = os.environ.get("TRUSTLENS_SAFEBROWSING_KEY", "")

    # Rate limiting (requests per minute per IP, per window).
    RATE_LIMIT_WINDOW = 60
    LOGIN_LIMIT = 8
    REGISTER_LIMIT = 4
    SCAN_LIMIT = 20

    # --- Session / security -------------------------------------------------
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
