"""
TrustLens - AI Based Information Verification System
utils.py - real analysis engines, scoring, PDF generation, rate limiting.

Design rules honoured here:
  * Every trust score is computed from the actual evidence extracted from the
    input (OCR output, image metrics, link inspection, network responses...).
  * Scores are never hardcoded and never defaulted to 100.
  * When there is not enough evidence, the scanner returns status="insufficient"
    with trust_score=None and the UI shows "Insufficient Evidence" instead of a
    fabricated number.
  * When live network verification cannot run, scanners say so explicitly.
"""

import io
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from flask import current_app, request

# --- Optional heavy dependencies (graceful degradation) ---------------------
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:  # pragma: no cover
    HAS_NUMPY = False

try:
    import cv2
    HAS_CV2 = True
except ImportError:  # pragma: no cover
    HAS_CV2 = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:  # pragma: no cover
    HAS_BS4 = False

try:
    import sklearn
    from sklearn.feature_extraction.text import TfidfVectorizer
    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False

try:
    from PIL import Image, ImageStat
    from PIL.ExifTags import TAGS as EXIF_TAGS
    HAS_PIL = True
except ImportError:  # pragma: no cover
    HAS_PIL = False

try:
    import pypdf
    HAS_PYPDF = True
except ImportError:  # pragma: no cover
    HAS_PYPDF = False

try:
    import whois as pywhois
    HAS_WHOIS = True
except ImportError:  # pragma: no cover
    HAS_WHOIS = False

try:
    import easyocr
    _EASYOCR_READER = None
    HAS_EASYOCR = True
except ImportError:  # pragma: no cover
    HAS_EASYOCR = False

# pyzbar can be installed but its bundled zbar DLL may fail to load on Windows;
# treat that as "unavailable" so OpenCV remains the fallback.
try:
    from pyzbar.pyzbar import decode as zbar_decode
    HAS_PYZBAR = True
except Exception:  # pragma: no cover - import or DLL load failure
    HAS_PYZBAR = False

try:
    import reportlab
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor, white
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable)
    from reportlab.lib.styles import ParagraphStyle
    HAS_REPORTLAB = True
except ImportError:  # pragma: no cover
    HAS_REPORTLAB = False

# --------------------------------------------------------------------------- #
#  Signature databases
# --------------------------------------------------------------------------- #

HIGH_PRESSURE_KEYWORDS = [
    "urgent", "immediate action required", "act now", "act immediately",
    "account suspended", "account blocked", "account frozen", "account on hold",
    "verify your account", "account verification required", "unusual activity",
    "lottery winner", "you have won", "congratulations you have been selected",
    "claim now", "claim your prize", "claim your reward", "limited time",
    "offer expires", "expires today", "last chance", "processing fee",
    "security deposit", "registration fee", "advance fee", "pay to release",
    "release your funds", "unlock your winnings", "bank details required",
    "confirm your password", "password expired", "update your payment",
    "gift card", "western union", "money gram", "wire transfer",
    "cryptocurrency payment", "tax refund", "unclaimed funds", "inheritance",
    "next of kin", "jackpot", "prize money", "guaranteed returns",
    "exclusive offer", "your account has been locked", "pay immediately",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online",
    ".site", ".click", ".link", ".buzz", ".live", ".work", ".zip", ".mov",
    ".gdn", ".pw", ".icu", ".men", ".loan", ".win", ".bid", ".rest", ".wang",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "rebrand.ly",
    "cutt.ly", "shorturl.at", "buff.ly", "rb.gy",
}

PAYMENT_WORDS = ["pay", "payment", "payable", "deposit", "transfer", "remit",
                 "upi", "fee", "bank account", "banking details"]
REWARD_WORDS = ["reward", "prize", "winnings", "jackpot", "cashback", "gift",
                "refund", "cash", "bonus"]

# Prize / lottery / financial lures. A hit here is a strong scam signal.
PRIZE_LURE_KEYWORDS = [
    "lottery", "you won", "you have won", "won a", "winner", "winning",
    "prize", "claim your", "cash prize", "jackpot", "lucky draw",
    "gift card", "raffle", "scratch card", "grand prize", "cash reward",
]

# Money terminology. On its own it is normal; combined with other signals it
# supports a fake-winnings / advance-fee verdict.
MONEY_TERMS = ["rupees", "rs.", "inr", "cash", "money", "amount", "lakh"]

# Requests for credentials, one-time passwords or verification codes.
CREDENTIAL_REQUEST_KEYWORDS = [
    "otp", "one time password", "verification code", "verify otp",
    "share your otp", "give the otp", "send otp", "send the otp",
    "bank pin", "your pin", "enter your pin", "password",
    "confirm your password", "update your password", "verify your account",
    "confirm your account", "unlock your account", "sent to your number",
    "sent to your mobile", "send money", "send to this number",
    "send to this upi", "banking details", "account details",
    "card details", "update your details",
]

# Below this length a clean score is never presented as "trustworthy" -
# there is too little content to justify a confident high verdict.
SHORT_TEXT_LIMIT = 100

UNVERIFIED_MERCHANT_PATTERNS = [
    r"unverified merchant",
    r"merchant.{0,40}(unverified|not verified|invalid|verify|pending)",
    r"upi.{0,40}(collect|request).{0,40}(verify|unknown|confirm)",
    r"collect request",
    r"(gpay|phonepe|paytm|bharatpe).{0,20}(id|merchant)",
    r"send money to this (number|upi|id)",
]

FREE_MAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                     "yahoo.co.in", "aol.com", "protonmail.com", "mail.com",
                     "icloud.com", "rediffmail.com", "live.com"}

JOB_PLATFORM_DOMAINS = {
    "linkedin.com", "internshala.com", "naukri.com", "indeed.com",
    "glassdoor.com", "foundit.in", "monsterindia.com", "shine.com",
    "timesjobs.com",
}

JOB_FEE_PHRASES = [
    "registration fee", "processing fee", "security deposit", "joining fee",
    "training fee", "refundable deposit", "refundable fee", "pay to confirm",
    "pay to apply", "money to release", "advance payment", "first investment",
    "pay first", "pay a fee",
]

# Redirection to personal chat apps - a hallmark of recruitment/internship scams.
JOB_CHAT_REDIRECT_KEYWORDS = [
    "contact on whatsapp", "contact us on whatsapp", "message us on whatsapp",
    "whatsapp number", "whatsapp group", "join whatsapp", "contact on telegram",
    "chat on telegram", "telegram group", "join telegram", "telegram channel",
    "telegram id", "connect on telegram",
]

# "Easy money" workflow tactics reused in fake job/internship offers.
# These trigger deductions (not the hard override) because similar phrases can
# legitimately appear in real postings.
JOB_SCAM_WORKFLOW_KEYWORDS = [
    "data entry job", "data entry work", "typing job", "type typing job",
    "part time online job", "part-time online job", "online part time job",
    "earn daily", "daily earning", "lakh per month", "lakhs per month",
    "earn from home", "earn money online",
]

# Phrases suggesting the posting claims to represent an established entity.
COMPANY_CLAIM_RE = re.compile(
    r"\b(?:company|corporation|corp|pvt\s*ltd|private\s*limited|ltd\.?|"
    r"limited|incorporated|inc\.?|organisation|organization|agency|firm)\b",
    re.IGNORECASE)

# Compulsory paid training - a clear internship/job scam trigger. No genuine
# employer charges a candidate for training.
PAID_TRAINING_PHRASES = [
    "paid training", "training fee", "training cost", "training charges",
    "compulsory training", "compulsory paid training", "must complete paid training",
    "training program fee", "pay for training", "fee for training",
    "stipend after training", "training will be charged", "training amount",
    "refundable training fee",
]

# "Certificate mill" wording - offers that sell certificates instead of work.
CERTIFICATE_MILL_PHRASES = [
    "certificate of internship", "internship certificate", "completion certificate",
    "certificate will be provided", "certificate will be issued",
    "certificate provided", "certificate only", "work for certificate",
    "certificate for free", "free certificate", "verified certificate",
    "certificate recognized", "certificate recognised",
    "certificate and offer letter",
]

# Domains repeatedly flagged in student complaints and cyber-cell advisories
# for fake / low-quality internship & certificate offers (2022-2026).
SUSPICIOUS_JOB_DOMAINS = {
    "codesoft.net", "codesoft.com", "codsoft.com", "codsoft.net",
    "mainflowservices.com", "softnexis.com", "codealpha.com", "prodology.com",
    "nullclass.in", "labmentix.com", "blackcoffer.com", "superassistant.in",
    "stamurai.com", "quadbtech.com", "cipherschools.com", "anorgtech.com",
    "itnetworkz.com", "kiransacademy.com", "softronix.com", "bharatintern.com",
    "oasisinfobyte.com", "cognifyz.com", "webalive.in", "internpe.in",
    "mindshiftech.com", "octanet.in", "innovatmetrics.com", "teachnook.in",
    "skilforge.com", "interntech.in", "halointern.in", "hexsoftware.com",
    "devserve.co.in", "technohacks.co.in", "edutantr.in", "pinnacleintern.in",
    "futureintern.in", "logiccell.in", "internshipstudio.com", "gaotek.com",
    "sparkllt.com", "encryptix.in", "verzeo.com", "orbitor.in", "skolar.in",
    "codingsamurai.com", "younity.in", "skybugtech.com", "lernx.in",
    "spehre.io", "prodigyinfotech.com", "softechfoundation.com",
    "losscoder.in", "codtech.in", "skillfied.com", "eduveda.in",
    "skybridgeintern.com", "technohacks.com", "internshala-clone.com",
}

# Company/platform names (word-boundary safe) matched against posting text and
# domains. "codesoft"/"codsoft" include lookalikes of the genuine codsoft.in.
SUSPICIOUS_JOB_NAMES = [
    "codesoft", "codsoft", "mainflow", "softnexis", "codealpha", "prodology",
    "nullclass", "labmentix", "blackcoffer", "superassistant", "super assistant",
    "stamurai", "quadbtech", "cipherschools", "cipher schools", "anorgtech",
    "anorg tech", "itnetworkz", "it networkz", "kiransacademy", "kiran academy",
    "softronix", "bharatintern", "bharat intern", "oasisinfobyte",
    "oasis infobyte", "cognifyz", "webalive", "internpe", "mindshiftech",
    "octanet", "innovatmetric", "teachnook", "skilforge", "interntech",
    "halointern", "hexsoftware", "devserve", "technohacks", "edutantr",
    "pinnacleintern", "pinnacle intern", "futureintern", "future intern",
    "logiccell", "logic cell", "internshipstudio", "internship studio",
    "gaotek", "sparkllt", "encryptix", "verzeo", "orbitor", "skolar",
    "codingsamurai", "coding samurai", "younity", "skybugtech", "skybug",
    "lernx", "spehre", "prodigyinfotech", "prodigy infotech",
    "softechfoundation", "softech foundation", "losscoder", "codtech",
    "skillfied", "eduveda",
]


def _is_suspicious_job_domain(host):
    """True when a host matches a flagged fake-internship domain/name."""
    host = (host or "").lower().strip(".")
    if not host:
        return False
    base = ".".join(host.split(".")[-2:])
    if host in SUSPICIOUS_JOB_DOMAINS or base in SUSPICIOUS_JOB_DOMAINS:
        return True
    return any(n in host for n in SUSPICIOUS_JOB_NAMES)


def _find_suspicious_job_refs(lower):
    """Return flagged company/platform names found in text (word-boundary safe)."""
    hits = []
    for n in SUSPICIOUS_JOB_NAMES:
        if re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", lower):
            hits.append(n)
    return hits

UNREALISTIC_SALARY = [
    (r"(?:₹|rs\.?|inr)\s?[0-9,.]+\s?[lL](?:akh)?\s?/?\s?month", "Lakhs per month"),
    (r"salary.{0,12}\$[0-9,]{5,}", "Five-figure USD salary"),
    (r"(?:₹|rs\.?)\s?[0-9,.]+\s?per\s?(?:day|hour)", "Daily/hourly wage flagged"),
]

GRAMMAR_ISSUES = [
    (r"\b(?:alot|definately|recieve|seperate|wierd|untill|occured|accomodate)\b", "misspelling"),
    (r"\b(?:gud|plz|thx|congrats)\b", "text-speak"),
    (r"(?<!\.)\s{3,}", "excessive whitespace"),
]

CLICKBAIT_PATTERNS = [
    r"\byou won't believe\b", r"\bshocking\b", r"\bwill make you\b",
    r"\bwhat happens next\b", r"\bnumber \d\b", r"\bshared \d+ times\b",
    r"\bdoctors hate\b", r"\bsecret\b", r"\bmiracle\b", r"\bthey don't want\b",
]

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure", "account", "confirm", "wallet", "bonus",
    "prize", "claim", "winner", "refund", "bank", "password", "update-payment",
    "free-gift", "reward",
]

# Example documents for similarity-based scam detection (real patterns).
SCAM_CORPUS = [
    "URGENT your account has been suspended. Verify now by clicking the link and entering your password or it will be blocked.",
    "Congratulations you are the lottery winner. Claim your prize now by paying a small processing fee via bank transfer.",
    "Dear candidate we are pleased to offer you work from home. Pay registration fee to reserve your seat. Immediate action required.",
    "Your parcel is held at customs. Pay a delivery fee of 500 rupees to release your package using UPI collect.",
    "We detected unusual activity. Confirm your banking details immediately or your card will be frozen.",
    "You have inherited unclaimed funds from a relative. Contact our lawyer and pay a security deposit to receive it.",
    "Click here to claim your cashback gift card before the offer expires today.",
    "Your password has expired. Update your payment details to keep your account active.",
    "Send money to this UPI id to unlock your winnings from the lucky draw.",
    "Western Union transfer required to release your tax refund. Act now.",
    "You won a lottery of rupees 5000. Congratulations! Share the OTP sent to your number to claim your prize.",
    "Enter your bank PIN and the OTP to verify your account and release your unclaimed lottery winnings.",
]

CLEAN_CORPUS = [
    "Hi please find attached the minutes from yesterday's meeting. We will schedule a follow-up next week.",
    "Your order has been shipped and will arrive within three working days. Track it from your account.",
    "Reminder: the project deadline is Friday. Let me know if you have any questions about the requirements.",
    "Thank you for subscribing. You will receive our newsletter every Monday morning.",
]

# --------------------------------------------------------------------------- #
#  Ingredient database (product ingredient scanner)
#  Each entry: canonical name -> (risk, why, aliases)
#    risk: "safe" | "moderate" | "high"
#    aliases: INCI names, E-numbers, CI numbers and common spellings
# --------------------------------------------------------------------------- #

INGREDIENT_DB = {
    # --- Base / safe ---
    "water": ("safe", "Purified base ingredient; safe.", ("aqua",)),
    "aqua": ("safe", "Purified water base; safe.", ()),
    "glycerin": ("safe", "Humectant that holds moisture; safe.",
                 ("glycerol", "glycerine")),
    "hyaluronic acid": ("safe", "Hydrating humectant found naturally in skin; safe.",
                        ("sodium hyaluronate", "hyaluronate")),
    "aloe vera": ("safe", "Soothing botanical; safe for most skin types.",
                  ("aloe barbadensis", "aloe barbadensis leaf juice", "aloe leaf juice")),
    "vitamin e": ("safe", "Antioxidant that protects skin oils; safe.",
                  ("tocopherol", "tocopheryl acetate", "alpha tocopherol")),
    "niacinamide": ("safe", "Vitamin B3 - restores barrier and evens tone; safe.",
                    ("nicotinamide", "vitamin b3")),
    "citric acid": ("safe", "pH balancer and natural preservative aid; safe.", ("e330",)),
    "ascorbic acid": ("safe", "Vitamin C - antioxidant; safe.", ("vitamin c", "e300", "l-ascorbic acid")),
    "vitamin c": ("safe", "Beneficial antioxidant (ascorbic acid).", ()),
    "panthenol": ("safe", "Provitamin B5 - moisturiser; safe.", ("provitamin b5", "vitamin b5")),
    "salicylic acid": ("safe", "Beta-hydroxy acid (BHA) exfoliant - generally safe topically; patch-test if sensitive.",
                       ("2-hydroxybenzoic acid",)),
    "allantoin": ("safe", "Skin-soothing agent; safe.", ()),
    "glycerol": ("safe", "Humectant; safe.", ()),
    "dimethicone": ("safe", "Silicone that smooths skin; generally safe.", ("silicone",)),
    "cyclomethicone": ("safe", "Volatile silicone; generally safe.", ()),
    "squalane": ("safe", "Botanical emollient; safe.", ()),
    "cetearyl alcohol": ("safe", "Fatty alcohol emollient; safe.", ("cetostearyl alcohol",)),
    "cetyl alcohol": ("safe", "Fatty alcohol; safe.", ()),
    "stearyl alcohol": ("safe", "Fatty alcohol; safe.", ()),
    "propylene glycol": ("safe", "Humectant; generally safe, mild irritant for a few.", ("1,2-propanediol",)),
    "butylene glycol": ("safe", "Humectant; safe.", ()),
    "caprylic/capric triglyceride": ("safe", "Coconut-derived emollient; safe.", ("caprylic capric triglyceride",)),
    "lanolin": ("safe", "Wool-derived emollient; safe, rare wool allergy.", ()),
    "zinc oxide": ("safe", "Mineral sunscreen/soothing agent; safe.", ("zinc oxide nf",)),
    "titanium dioxide": ("moderate", "Banned as a food additive (E171) in the EU; safe in mineral sunscreens, "
                         "but avoid inhalation of sprays.",
                         ("e171", "ci 77891")),
    "avobenzone": ("safe", "Chemical sunscreen filter; generally safe.", ("butyl methoxydibenzoylmethane",)),
    "avena sativa": ("safe", "Oat extract - soothing; safe.", ("oat extract", "oatmeal")),
    "oat extract": ("safe", "Soothing oat botanical; safe.", ("avena sativa extract",)),
    "green tea extract": ("safe", "Antioxidant botanical; safe.", ("camellia sinensis extract",)),
    "chamomile": ("safe", "Soothing botanical; safe.", ("chamomilla recutita", "chamomile extract")),
    "lavender": ("safe", "Soothing botanical; safe when patch-tested.", ("lavandula", "lavandula angustifolia")),
    "tea tree": ("safe", "Botanical antibacterial; safe when patch-tested.", ("melaleuca", "melaleuca alternifolia")),
    "jojoba": ("safe", "Nourishing botanical oil; safe.", ("jojoba oil", "simmondsia chinensis")),
    "argan": ("safe", "Nutrient-rich botanical oil; safe.", ("argan oil", "argania spinosa")),
    "rosehip": ("safe", "Regenerative botanical oil; safe.", ("rosehip oil", "rosa canina fruit oil")),
    "shea butter": ("safe", "Nourishing botanical butter; safe.", ("butyrospermum parkii", "shea butter extract")),
    "cocoa butter": ("safe", "Emollient botanical butter; safe.", ("theobroma cacao", "cocoa seed butter")),
    "beeswax": ("safe", "Natural emulsifier/wax; safe.", ("cera alba",)),
    "sodium chloride": ("safe", "Common salt - stabiliser; safe.", ("salt", "table salt")),
    "sodium bicarbonate": ("safe", "Leavening agent / buffering; safe.", ("baking soda", "e500")),
    "soy lecithin": ("safe", "Common emulsifier; safe.", ("lecithin", "e322")),
    "xanthan gum": ("safe", "Natural thickener; safe.", ("e415",)),
    "guar gum": ("safe", "Natural thickener; safe.", ("e412",)),
    "sorbitol": ("safe", "Sugar alcohol sweetener; safe in moderation.", ("e420",)),
    "xylitol": ("safe", "Sugar alcohol sweetener; safe in moderation, toxic to dogs.", ("e967",)),
    "erythritol": ("safe", "Sugar alcohol sweetener; safe.", ("e968",)),
    "maltodextrin": ("safe", "Common carbohydrate thickener; safe.", ()),
    "maize starch": ("safe", "Corn-derived starch - common thickener/binder; safe.",
                     ("corn starch", "cornflour", "corn flour", "zea mays starch")),
    "tapioca starch": ("safe", "Cassava-derived starch - common thickener/binder; safe.",
                       ("tapioca", "cassava starch", "manioc starch")),
    "stevia": ("safe", "Natural zero-calorie sweetener; safe.", ("steviol glycosides", "reb a", "rebiana")),
    "mono and diglycerides": ("safe", "Common food emulsifier; safe.", ("mono- and diglycerides", "e471")),
    "potassium sorbate": ("safe", "Widely used preservative (E202); safe.", ("e202",)),
    "sorbic acid": ("safe", "Natural preservative (E200); safe.", ("e200",)),
    "sodium citrate": ("safe", "Buffering salt; safe.", ("e331",)),
    "calcium propionate": ("safe", "Mold-inhibiting preservative (E282); safe.", ("e282",)),
    "sodium propionate": ("safe", "Mold-inhibiting preservative (E281); safe.", ("e281",)),
    "potassium chloride": ("safe", "Salt substitute; safe.", ("e508",)),
    "whole wheat flour": ("safe", "Whole grain; safe.", ("wholemeal flour",)),
    "milk": ("safe", "Natural dairy ingredient.", ()),
    "coconut oil": ("safe", "Natural oil; high saturated fat in excess.", ("coconut",)),
    "olive oil": ("safe", "Heart-healthy fat; safe.", ("olive",)),
    "sunflower oil": ("safe", "Common cooking oil; safe.", ("sunflower",)),
    "canola oil": ("safe", "Common cooking oil; safe.", ("rapeseed oil",)),
    "calcium": ("safe", "Essential mineral.", ("calcium carbonate",)),
    "iron": ("safe", "Essential mineral.", ("ferrous", "ferric")),
    "folic acid": ("safe", "Essential vitamin (B9).", ("vitamin b9", "folate")),
    "vitamin b12": ("safe", "Essential vitamin.", ("cyanocobalamin",)),
    "iodine": ("safe", "Essential mineral.", ("potassium iodide",)),
    "potassium": ("safe", "Essential mineral.", ()),
    "magnesium": ("safe", "Essential mineral.", ()),
    "zinc": ("safe", "Essential mineral.", ("zinc gluconate",)),
    "fiber": ("safe", "Dietary fibre; safe.", ("fibre", "dietary fibre")),
    "protein": ("safe", "Macronutrient; safe.", ("whey protein", "pea protein")),
    "vitamin d": ("safe", "Essential vitamin.", ("cholecalciferol", "ergocalciferol")),
    "vitamin a": ("safe", "Essential vitamin.", ("retinyl acetate",)),
    "vitamin k": ("safe", "Essential vitamin.", ()),
    # Staple foods & spices (edible products)
    "potato": ("safe", "Starchy vegetable - safe.", ("potato starch", "potato flour", "aloo")),
    "wheat": ("safe", "Cereal grain - safe; contains gluten.", ("whole wheat", "wheat flour", "atta")),
    "rice": ("safe", "Staple grain - safe.", ("rice flour", "rice starch", "rice bran oil")),
    "spices": ("safe", "Spice blend - safe.", ("masala", "mixed spices", "garam masala")),
    "cumin": ("safe", "Aromatic spice - safe.", ("jeera", "cumin seed", "cumin powder")),
    "ginger": ("safe", "Spice with anti-inflammatory properties - safe.", ("adrak", "ginger powder", "ginger root")),
    "black pepper": ("safe", "Common spice - safe.", ("pepper", "peppercorn", "kali mirch", "black peppercorn")),
    "garlic": ("safe", "Aromatic bulb spice - safe.", ("lahsun", "garlic powder", "garlic flakes")),
    "cinnamon": ("safe", "Aromatic bark spice - safe.", ("dalchini", "cinnamon powder", "cassia")),

    # --- Moderate / caution ---
    "sugar": ("moderate", "Added sugar - excess intake linked to metabolic issues.", ("cane sugar", "white sugar")),
    "sucrose": ("moderate", "Refined sugar.", ()),
    "salt": ("moderate", "High sodium intake is a health risk.", ("sodium chloride",)),
    "sodium": ("moderate", "High sodium intake is a health risk.", ()),
    "palm oil": ("moderate", "High saturated fat; environmental concerns.",
                 ("refined palm oil", "palm olein")),
    "palmolein": ("moderate", "High saturated fat.", ("palmolein oil",)),
    "palm kernel oil": ("moderate", "High saturated fat.", ()),
    "maida": ("moderate", "Refined flour - low fibre.", ("all purpose flour",)),
    "refined wheat flour": ("moderate", "Refined flour - low fibre.", ()),
    "corn syrup": ("moderate", "High sugar syrup; not the same as HFCS.", ()),
    "caramel color": ("moderate", "Processing can form contaminants; may contain 4-MEI.", ("e150",)),
    "sodium benzoate": ("moderate", "Preservative; caution with ascorbic acid (benzene risk).", ("e211",)),
    "potassium benzoate": ("moderate", "Preservative.", ("e212",)),
    "sulfur dioxide": ("moderate", "Preservative - allergen, can trigger asthma.", ("e220",)),
    "sodium metabisulfite": ("moderate", "Sulfite preservative - allergen, asthma risk.", ("e223",)),
    "potassium metabisulfite": ("moderate", "Sulfite preservative - allergen.", ("e224",)),
    "sodium sulfite": ("moderate", "Sulfite preservative - allergen.", ("e221",)),
    "sulfites": ("moderate", "Sulfite additives - allergen; can trigger asthma.", ("sulphites", "sulfite")),
    "carrageenan": ("moderate", "Thickener; digestive irritation in some sensitive people.", ("e407",)),
    "saccharin": ("moderate", "Artificial sweetener; still approved, label warnings in some regions.", ("e954",)),
    "sucralose": ("moderate", "Artificial sweetener; gut-flora concerns at high intake.", ("e955",)),
    "acesulfame": ("moderate", "Artificial sweetener.", ("acesulfame potassium", "acesulfame k", "e950")),
    "msg": ("moderate", "Monosodium glutamate - safe for most, sensitivity in some.", ("monosodium glutamate", "e621")),
    "monosodium glutamate": ("moderate", "Flavour enhancer - sensitivity in some people.", ("e621",)),
    "artificial flavor": ("moderate", "Synthetic flavouring - some may contain undisclosed additives.", ("artificial flavouring", "artificial flavour")),
    "artificial flavour": ("moderate", "Synthetic flavouring.", ("artificial flavor", "artificial flavouring")),
    "artificial colour": ("moderate", "Synthetic colouring - see specific dyes.", ("artificial color", "artificial colouring")),
    "artificial color": ("moderate", "Synthetic colouring.", ()),
    "fd&c": ("moderate", "Synthetic dye prefix - check the specific dye for risk.", ("fd c", "food colour", "food color")),
    "talc": ("moderate", "May be contaminated with asbestos in unregulated sources.", ("talcum",)),
    "mineral oil": ("moderate", "Petroleum-derived; refined grades are safe, unrefined may contain impurities.", ("liquid paraffin", "paraffinum liquidum")),
    "petrolatum": ("moderate", "Refined petroleum jelly is safe; unrefined may contain PAHs.", ("petroleum jelly", "vaseline")),
    "retinol": ("moderate", "Vitamin A - increases sun sensitivity; avoid in pregnancy at high doses.", ("vitamin a alcohol",)),
    "retinyl palmitate": ("moderate", "Vitamin A ester - may increase photosensitivity.", ("retinyl acetate",)),
    "homosalate": ("moderate", "Chemical sunscreen filter - possible endocrine effects.", ()),
    "octinoxate": ("moderate", "Chemical sunscreen filter - possible endocrine effects; reef concern.", ("octyl methoxycinnamate", "ethylhexyl methoxycinnamate")),
    "cocamidopropyl betaine": ("moderate", "Mild surfactant; a known contact allergen for some.", ("capb",)),
    "triethanolamine": ("moderate", "TEA - may form nitrosamines; irritation at high levels.", ("tea", "trolamine")),
    "blue 2": ("moderate", "Indigo Carmine (E132) - artificial dye, hyperactivity concerns.", ("indigo carmine", "indigotine", "e132", "ci 73015", "fd&c blue 2")),
    "green 3": ("moderate", "Fast Green FCF (E143) - artificial dye.", ("fast green", "e143", "ci 42053")),
    "benzalkonium chloride": ("moderate", "Antiseptic preservative - safe at low levels, irritant to some.", ("bkc",)),
    "phenoxyethanol": ("moderate", "Preservative; safe at low concentrations, irritant at higher.", ()),
    "aluminum chlorohydrate": ("moderate", "Antiperspirant salt; aluminium-exposure debates.", ()),
    "isopropyl alcohol": ("moderate", "Solvent - safe in small amounts, drying to skin.", ("isopropanol", "ipa")),
    "ethyl alcohol": ("moderate", "Solvent - drying to skin.", ("alcohol denat", "ethanol", "sd alcohol")),

    # --- High risk / unsafe ---
    # Parabens
    "methylparaben": ("high", "Paraben preservative - potential endocrine disruptor and contact allergen.",
                      ("methyl 4-hydroxybenzoate", "e218", "nipagin m")),
    "ethylparaben": ("high", "Paraben preservative - potential endocrine disruptor.",
                     ("e214", "ethyl 4-hydroxybenzoate")),
    "propylparaben": ("high", "Paraben preservative - potential endocrine disruptor.",
                      ("e216", "propyl 4-hydroxybenzoate")),
    "butylparaben": ("high", "Paraben preservative - potential endocrine disruptor.",
                     ("e209", "butyl 4-hydroxybenzoate")),
    "isobutylparaben": ("high", "Paraben preservative - potential endocrine disruptor.", ()),
    "isopropylparaben": ("high", "Paraben preservative - potential endocrine disruptor.", ()),
    "paraben": ("high", "Paraben preservative - potential endocrine disruptor.", ()),
    # Phthalates
    "dibutyl phthalate": ("high", "Phthalate plasticizer - potential endocrine disruptor and reproductive toxin; banned in EU cosmetics.",
                          ("dbp", "di-n-butyl phthalate")),
    "di(2-ethylhexyl) phthalate": ("high", "Phthalate - endocrine disruptor; banned in cosmetics in the EU.", ("dehp",)),
    "diethyl phthalate": ("high", "Phthalate - potential endocrine disruptor; used to hold fragrance.", ("dep",)),
    "butyl benzyl phthalate": ("high", "Phthalate - potential endocrine disruptor.", ("bbp", "benzyl butyl phthalate")),
    "dimethyl phthalate": ("high", "Phthalate - potential endocrine disruptor.", ("dmp",)),
    "phthalate": ("high", "Phthalate - potential endocrine disruptor; often hidden in 'fragrance'.", ()),
    # Formaldehyde releasers
    "formaldehyde": ("high", "Known carcinogen; banned in cosmetics in the EU.",
                     ("formalin", "methylene glycol", "methanal")),
    "dmdm hydantoin": ("high", "Formaldehyde releaser - skin sensitizer; linked to dermatitis.",
                       ("dimethylol dimethyl hydantoin",)),
    "quaternium-15": ("high", "Releases formaldehyde; strong allergen and irritant, restricted in the EU.", ()),
    "diazolidinyl urea": ("high", "Formaldehyde releaser - skin sensitizer.", ("germall ii",)),
    "imidazolidinyl urea": ("high", "Formaldehyde releaser - skin sensitizer.", ("germall 115",)),
    "bronopol": ("high", "Formaldehyde releaser - skin and respiratory sensitizer.", ("2-bromo-2-nitropropane-1,3-diol", "bromonitropropane diol")),
    "sodium hydroxymethylglycinate": ("high", "Formaldehyde releaser - skin sensitizer.", ()),
    # Sulfates
    "sodium lauryl sulfate": ("high", "Sulfate surfactant - can strip skin/natural oils and irritate; linked to contact dermatitis.",
                             ("sls", "monododecyl sulfate")),
    "sodium laureth sulfate": ("high", "Sulfate surfactant - harsh cleanser; irritant; may contain trace 1,4-dioxane.",
                               ("sles", "sodium lauryl ether sulfate")),
    "ammonium lauryl sulfate": ("high", "Sulfate surfactant - skin irritant.", ("als",)),
    # BHA / BHT
    "bha": ("high", "Butylated hydroxyanisole - IARC Group 2B possible carcinogen; endocrine concerns.",
            ("butylated hydroxyanisole", "e320")),
    "bht": ("high", "Butylated hydroxytoluene - possible carcinogen; endocrine concerns.",
            ("butylated hydroxytoluene", "e321")),
    # Other cosmetics / preservatives
    "triclosan": ("high", "Antibacterial - potential endocrine disruptor; restricted by the FDA.", ()),
    "fragrance": ("high", "Fragrance blend - common skin sensitizer; may conceal undisclosed phthalates.",
                  ("parfum", "perfume", "synthetic fragrance", "aroma compound", "fragrance oil")),
    "parfum": ("high", "Fragrance mixture - common allergen; may hide phthalates.", ("fragrance", "perfume")),
    # EU-declared fragrance allergens
    "hexyl cinnamal": ("high", "Fragrance allergen - EU requires label declaration; common contact sensitizer.",
                       ("hexyl cinnamaldehyde", "hexyl cinnamic aldehyde")),
    "citronellol": ("high", "Fragrance allergen - EU requires label declaration; common contact sensitizer.",
                    ("dihydromyrcenol",)),
    "geraniol": ("high", "Fragrance allergen - EU requires label declaration; common contact sensitizer.", ()),
    "linalool": ("high", "Fragrance allergen - EU requires label declaration; oxidises into stronger sensitisers.", ()),
    "limonene": ("high", "Fragrance allergen - EU requires label declaration; oxidised forms are sensitisers.", ("d-limonene",)),
    "citral": ("high", "Fragrance allergen - EU requires label declaration; contact sensitizer.", ("geranial", "neral")),
    "eugenol": ("high", "Fragrance allergen - EU requires label declaration.", ()),
    "coumarin": ("high", "Fragrance allergen - EU requires label declaration.", ()),
    "toluene": ("high", "Neurotoxic solvent - restricted in nail and hair products.", ("methylbenzene",)),
    "hydroquinone": ("high", "Skin-lightening agent - banned in many regions; irritation and pigmentation risk.", ()),
    "lead acetate": ("high", "Lead-based dye - banned in cosmetics.", ()),
    "mercury": ("high", "Mercury compounds - banned in cosmetics; neurotoxic.", ("mercuric", "thiomersal")),
    "thiomersal": ("high", "Mercury-based preservative - neurotoxin concerns.", ("thimerosal",)),
    "oxybenzone": ("high", "Chemical sunscreen - potential endocrine disruptor; reef-harming, banned in some regions.",
                   ("benzophenone-3", "benzophenone 3")),
    "benzophenone": ("high", "UV filter - potential endocrine disruptor.", ("benzophenone-3", "bp-3")),
    "cocamide dea": ("high", "Surfactant - may form carcinogenic nitrosamines; restricted in the EU.",
                     ("coco diethanolamide",)),
    "cocamide mea": ("high", "Surfactant - may form carcinogenic nitrosamines.", ("coco monoethanolamide",)),
    "diethanolamine": ("high", "DEA - may form carcinogenic nitrosamines; restricted in the EU.", ("dea", "2,2'-iminodiethanol")),
    "methylchloroisothiazolinone": ("high", "MI/MCI preservative - strong contact allergen; sensitizing.",
                                    ("mci", "kathon cg", "e297")),
    "methylisothiazolinone": ("high", "MI preservative - strong contact allergen, even in tiny amounts.", ("mi",)),
    # Trans fats
    "partially hydrogenated oil": ("high", "Trans fat - raises LDL cholesterol, lowers HDL; linked to heart disease.", ()),
    "partially hydrogenated": ("high", "Trans fat source - linked to heart disease.", ()),
    "hydrogenated vegetable oil": ("high", "May contain trans fats - linked to heart disease.", ()),
    "hydrogenated": ("high", "Hydrogenated fat - may contain trans fats, linked to heart disease.", ()),
    "shortening": ("high", "Vegetable shortening - typically hydrogenated, may contain trans fats.", ("vegetable shortening",)),
    # Artificial dyes
    "red 40": ("high", "Allura Red AC (E129) - artificial dye linked to hyperactivity in children.",
               ("allura red", "allura red ac", "e129", "ci 16035", "fd&c red 40", "fd&c red no 40", "red no 40", "red 40 lake")),
    "yellow 5": ("high", "Tartrazine (E102) - artificial dye linked to hyperactivity; possible allergen.",
                 ("tartrazine", "e102", "ci 19140", "fd&c yellow 5", "fd&c yellow no 5", "yellow no 5")),
    "yellow 6": ("high", "Sunset Yellow (E110) - artificial dye linked to hyperactivity.",
                 ("sunset yellow", "sunset yellow fcf", "e110", "ci 15985", "fd&c yellow 6", "yellow no 6")),
    "blue 1": ("high", "Brilliant Blue (E133) - artificial dye; hyperactivity concerns.",
               ("brilliant blue", "brilliant blue fcf", "e133", "ci 42090", "fd&c blue 1", "fd&c blue no 1", "blue no 1")),
    "red 3": ("high", "Erythrosine (E127) - artificial dye banned in some regions over thyroid concerns.",
              ("erythrosine", "e127", "ci 45430", "fd&c red 3")),
    # Other food additives
    "potassium bromate": ("high", "Flour improver - possible carcinogen; banned in the EU, UK and India.",
                          ("e924", "bromate")),
    "sodium nitrite": ("high", "Cured-meat preservative - can form carcinogenic nitrosamines.",
                       ("nitrite", "e250")),
    "sodium nitrate": ("high", "Cured-meat preservative - can form carcinogenic nitrosamines.",
                       ("nitrate", "e251", "potassium nitrate", "e252")),
    "high fructose corn syrup": ("high", "HFCS - linked to obesity, insulin resistance and metabolic disorders.",
                                 ("hfcs", "isoglucose")),
    # INS / E-number flavour enhancers and processing aids
    "disodium guanylate": ("moderate", "INS 627 / E627 - flavour enhancer with high purine content; relevant to gout sufferers.",
                           ("guanylate", "e627", "ins 627", "disodium 5'-guanylate")),
    "disodium inosinate": ("moderate", "INS 631 / E631 - flavour enhancer with high purine content; relevant to gout sufferers.",
                           ("inosinate", "e631", "ins 631", "disodium 5'-inosinate")),
    "silicon dioxide": ("moderate", "INS 551 / E551 - anti-caking agent; generally safe in food, inhalation concern in powder form.",
                        ("silica", "e551", "ins 551", "silicic anhydride")),
    "malic acid": ("safe", "INS 296 / E296 - natural acidulant found in fruits; safe.",
                   ("e296", "ins 296", "dl-malic acid", "dl malic acid")),
    "aspartame": ("high", "Artificial sweetener - classified possible carcinogen (IARC 2B, 2023).",
                  ("e951", "nutrasweet")),
    "tbhq": ("high", "Tertiary-butylhydroquinone (E319) - synthetic antioxidant with health concerns at high doses.",
             ("tert-butylhydroquinone", "tertiary butyl hydroquinone", "e319")),
    "phosphoric acid": ("moderate", "Acidulant (E338) - excess intake may affect bone health.", ("e338",)),
}

# Worst-of-the-worst offenders: presence forces the score to a hard cap (High Risk).
SEVERE_INGREDIENTS = {
    "formaldehyde", "dmdm hydantoin", "quaternium-15", "diazolidinyl urea",
    "imidazolidinyl urea", "bronopol", "sodium hydroxymethylglycinate",
    "dibutyl phthalate", "di(2-ethylhexyl) phthalate", "butyl benzyl phthalate",
    "potassium bromate", "triclosan", "lead acetate", "mercury", "thiomersal",
}

# Generic "natural / botanical" wording treated as safe when no specific entry
# matches (e.g. "lavender essential oil", "grape seed extract").
SAFE_GENERIC_PATTERNS = [
    (r"\bessential oil", "Natural essential oil - generally safe; patch-test for sensitivity."),
    (r"\bextract\b", "Natural botanical extract - generally safe."),
    (r"\bplant oil\b", "Natural plant oil - generally safe."),
    (r"\bbotanical\b", "Natural botanical ingredient - generally safe."),
]

_INGREDIENT_LOOKUP = {}
for _name, (_risk, _why, _aliases) in INGREDIENT_DB.items():
    _INGREDIENT_LOOKUP[_name] = _name
    for _alias in _aliases:
        _INGREDIENT_LOOKUP.setdefault(_alias.strip().lower(), _name)


# --------------------------------------------------------------------------- #
#  Product type & usage-caution detection
# --------------------------------------------------------------------------- #

NON_EDIBLE_BANNER = ("🚨 NON-EDIBLE COSMETIC/PERSONAL CARE PRODUCT: Intended strictly for "
                     "external use. DO NOT CONSUME.")

EDIBLE_BANNER = "✅ EDIBLE PRODUCT: Formulated as a food or beverage item."

LOW_QUALITY_INGREDIENT_MSG = ("📷 Image Unreadable: Could not detect clear ingredient text. "
                              "Please upload a well-lit photo of the ingredient list.")

CAUTION_KEYWORDS = [
    "external use only", "not for internal use", "for external use only",
    "for external application", "for topical use only", "do not ingest",
    "not for oral use", "not to be taken", "not to be taken internally",
    "avoid contact with eyes", "keep away from children", "cosmetic product",
    "cosmetic use only", "for cosmetic use", "do not swallow", "not for ingestion",
]

# STRICT RULE: any one of these forces the product type to
# "Cosmetic / Personal Care (Non-Edible)". This list is checked BEFORE any food
# marker so a hair/skin/cosmetic product can never be mislabelled as an edible
# food item, even when its ingredients (starch, argan oil, aloe vera, ...) also
# occur in food.
COSMETIC_FORCE_KEYWORDS = [
    "hair", "shampoo", "conditioner", "serum", "keratin", "cosmetic",
    "scalp", "skin", "dandruff", "hairspray", "hair mask", "hair oil",
    "apply to wet hair", "for external use", "external application",
    "dermatologically tested", "lotion", "wipe",
    "face wash", "facial", "moisturiz", "cleanser", "toner", "sunscreen",
    "sunblock", "lipstick", "lip balm", "lip gloss", "mascara", "eyeshadow",
    "foundation", "concealer", "blush", "makeup", "nail polish", "nail lacquer",
    "cuticle", "perfume", "cologne", "eau de toilette", "toothpaste", "tooth gel",
    "mouthwash", "deodorant", "antiperspirant", "body wash", "shower gel",
] + CAUTION_KEYWORDS

# Product-type words that also appear on food labels (e.g. "cream" in "ice
# cream"); treated as cosmetic only when no food marker is present.
SOFT_COSMETIC_WORDS = [
    "cream", "gel", "soap", "face", "body", "bath", "beauty",
    "baby", "ointment",
]

# Words that identify an edible food / beverage product.
FOOD_CATEGORY_KEYWORDS = [
    "nutrition facts", "serving size", "calories", "dietary", "fssai",
    "exp date", "expiry date", "net wt", "net weight", "best before",
    "proprietary food", "ready-to-eat", "allergen advice",
    "per 100g", "per serving",
    "ice cream", "yogurt", "yoghurt", "curd", "paneer", "ghee", "cheese",
    "chocolate", "candy", "biscuit", "cookie", "chips", "noodles", "pasta",
    "juice", "sauce", "ketchup", "honey", "jam", "bread", "soup", "snack",
    "cereal", "breakfast", "dessert", "drink", "beverage", "edible", "consume",
    "serving", "kcal", "calorie", "flavor", "flavour", "eat",
    "flour", "wheat", "maida", "sugar",
]

PERSONAL_CARE_SUBCATEGORIES = {
    "Haircare": ["shampoo", "conditioner", "hair", "scalp", "dandruff", "hairspray"],
    "Skincare": ["face", "facial", "serum", "moisturiz", "cream", "lotion", "toner",
                 "cleanser", "sunscreen", "sunblock", "anti aging", "anti-aging",
                 "wrinkle", "blemish", "acne"],
    "Oral Care": ["toothpaste", "tooth", "mouthwash", "dental", "gum"],
    "Body / Bath": ["body", "bath", "shower", "soap", "deodorant", "antiperspirant"],
    "Makeup": ["lipstick", "lip balm", "foundation", "concealer", "eyeshadow",
               "mascara", "blush", "makeup"],
    "Nail Care": ["nail", "cuticle"],
    "Fragrance": ["perfume", "cologne", "eau de toilette"],
}


def _detect_product_category(lower_text):
    """Return (category, is_edible, caution_flags).

    Strict priority:
      1) ANY hair/skin/cosmetic/caution keyword  -> "Cosmetic / Personal Care
         (Non-Edible)" - never food, regardless of ingredient overlap.
      2) Food markers                             -> "Edible Food / Beverage".
      3) Ambiguous cosmetic words                 -> cosmetic (topical).
      4) Otherwise                                -> "Unidentified".

    is_edible: True (food), False (cosmetic / non-edible), None (unidentified).
    """
    lower_text = lower_text or ""
    flags = [c for c in CAUTION_KEYWORDS if c in lower_text]
    # Keep only the most specific phrase - drop any flag that is a substring of
    # another matched flag (e.g. "external use only" inside "for external use only").
    flags = [f for f in flags if not any(f != g and f in g for g in flags)]
    if any(k in lower_text for k in COSMETIC_FORCE_KEYWORDS):
        sub = _personal_care_subcategory(lower_text)
        cat = ("Cosmetic / Personal Care - %s (Non-Edible)" % sub if sub
               else "Cosmetic / Personal Care (Non-Edible)")
        return cat, False, flags
    if any(k in lower_text for k in FOOD_CATEGORY_KEYWORDS):
        return "Edible Food / Beverage", True, flags
    if any(k in lower_text for k in SOFT_COSMETIC_WORDS):
        sub = _personal_care_subcategory(lower_text)
        return ("Cosmetic / Personal Care - %s (Topical)" % sub if sub
                else "Cosmetic / Personal Care (Topical)"), False, flags
    return "Unidentified", None, flags


def _personal_care_subcategory(lower_text):
    for subcat, kws in PERSONAL_CARE_SUBCATEGORIES.items():
        if any(k in lower_text for k in kws):
            return subcat
    return ""


# Fuzzy ingredients header - tolerant of cropped, partial or misspelled headers
# such as "GREDIENTS:", "Ingred:", "Contains:", "Composition:".
INGREDIENT_HEADER_RE = re.compile(
    r"\b(?:\w{0,8}gredie?nts?|ingred\w*|contain(?:s|ing)?|"
    r"composition|composici[oó]n|composicao|inhaltsstoffe|bestanddelen|"
    r"lista\s+de\s+ingredientes)\b\s*(?:list\b\s*)?[:|\-–—]?\s*",
    re.I)

# Trailing label sections that end the ingredient block.
REGION_STOP_RE = re.compile(
    r"(?:\bnutrition facts\b|\bnutritional\b|\ballergen advice\b|\ballergens?\b|"
    r"\bbest before\b|\bexpiry\b|\bexp date\b|\bmfg\b|\bmanufactur|\bfssai\b|"
    r"\bcustomer care\b|\bstorage\b|\bdirections for use\b|\bwarning\b|"
    r"\bnet wt\b|\bnet weight\b|\bmade in\b|\bimported\b|\bmarketed by\b|"
    r"\bdistributed by\b|\bgstin\b|\bbatch no\b|\bbarcode\b|"
    r"\bwww\.\b|\bemail\b|\btel[:.]\b)",
    re.I)

# Chemical / food / cosmetic term stems used by the fallback extractor.
INGREDIENT_TERM_RE = re.compile(
    r"\b(?:acid|oil|extract|chloride|starch|sugar|gum|alcohol|ester|oxide|"
    r"sulfate|sulphate|paraben|fragrance|parfum|flavour|flavor|preservative|"
    r"antioxidant|emulsifier|colour|color|enzyme|protein|salt|aqua|water|"
    r"vitamin|bicarbonate|citrate|sorbate|benzoate|nitrite|nitrate|"
    r"phosphate|glutamate|guanylate|inosinate|sweetener|thickener|butter|"
    r"spice|milk|wheat|rice|potato|flour|syrup|glucose|fructose|dextrose|"
    r"lactose|maltodextrin|cellulose|glycer|sodium|potassium|calcium|"
    r"magnesium|zinc|iron|silicon|titanium|aloe|cinnamal|citronellol|"
    r"salicylic|hyaluronic|niacinamide|panthenol|collagen|keratin|"
    r"dimethicone|silicone|urea|hydroxide)\b",
    re.I)


def _extract_ingredient_region(text):
    """Return (region, method, matched_header).

    method:
      "header"   - a fuzzy ingredients header was found; region trimmed after it.
      "fallback" - no header; the comma-separated ingredient-term block was used.
      "full"     - no useful header/block found; region is the whole text.
    """
    if not text:
        return "", "full", None
    m = INGREDIENT_HEADER_RE.search(text)
    if m:
        region = text[m.end():]
        stop = REGION_STOP_RE.search(region)
        if stop:
            region = region[:stop.start()]
        return region.strip(), "header", m.group(0).strip()
    # Fallback: locate the block of comma-separated ingredient terms.
    lines = re.split(r"[\n\r]+", text)
    start_idx = None
    for i, ln in enumerate(lines):
        if ln.count(",") >= 1 and INGREDIENT_TERM_RE.search(ln):
            start_idx = i
            break
    if start_idx is not None:
        block = "\n".join(lines[start_idx:])
        stop = REGION_STOP_RE.search(block)
        if stop:
            block = block[:stop.start()]
        if block.count(",") >= 2:
            return block.strip(), "fallback", None
    return text.strip(), "full", None


def _parse_ingredients(raw_text):
    """Normalize OCR label text into a clean, de-duplicated list of ingredients."""
    if not raw_text:
        return []
    text = raw_text
    text = re.sub(r"\bmay contain[^,;]*?(?:milk|soy|egg|wheat|peanut|tree nut|fish|shellfish|sesame|gluten|mustard|cereal)[^,;]*",
                  " ", text, flags=re.I)
    text = re.sub(r"\b(?:ingredients?|ingr[ée]dients?|inhaltsstoffe|composici[oó]n|"
                  r"lista de ingredientes|bestanddelen)\b\s*[:|]?", " ", text, flags=re.I)
    # Drop bracketed annotations like "(E129)" or "(5%)".
    text = re.sub(r"\([^)]*\)", " ", text)
    text = re.sub(r"\[[^\]]*\]", " ", text)
    # Drop explicit percentages / quantities.
    text = re.sub(r"\b\d+(?:\.\d+)?\s*%", " ", text)
    # Treat bullets, pipes, slashes and newlines as separators.
    text = re.sub(r"[•·|/\t\n\r]+", ",", text)
    text = text.replace(";", ",")
    tokens = []
    for raw in text.split(","):
        tok = re.sub(r"[^a-zA-Z0-9&'\-. ]+", " ", raw)
        tok = re.sub(r"\bno\b", " ", tok)  # "FD&C Red No. 40" -> "fd&c red 40"
        tok = re.sub(r"\s+", " ", tok).strip(" .-").lower()
        if len(tok) < 2 or tok.isdigit() or tok in ("and", "or", "contains"):
            continue
        tokens.append(tok)
    seen, out = set(), []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _match_ingredient(token):
    """Return the canonical ingredient name for a token, or None."""
    t = token.strip()
    if t in _INGREDIENT_LOOKUP:
        return _INGREDIENT_LOOKUP[t]
    candidates = []
    for name in INGREDIENT_DB:
        if len(name) >= 4 and name in t:
            candidates.append(name)
        elif len(t) >= 4 and t in name:
            candidates.append(name)
    # Prefer the most specific (longest) match, e.g. "sodium lauryl sulfate"
    # over "sodium".
    if candidates:
        return max(candidates, key=len)
    return None


def _classify_ingredients(tokens):
    """Split tokens into safe / moderate / high / unknown ingredient records."""
    safe, moderate, high, unknown = [], [], [], []
    seen = set()
    for tok in tokens:
        canon = _match_ingredient(tok)
        if canon is None:
            matched_generic = next((why for pat, why in SAFE_GENERIC_PATTERNS
                                    if re.search(pat, tok)), None)
            if matched_generic:
                canon = tok
                safe.append({"name": tok, "original": tok, "risk": "safe",
                             "why": matched_generic})
                seen.add(canon)
            else:
                unknown.append(tok)
            continue
        if canon in seen:
            continue
        seen.add(canon)
        risk, why, _ = INGREDIENT_DB[canon]
        rec = {"name": canon, "original": tok, "risk": risk, "why": why}
        (safe if risk == "safe" else moderate if risk == "moderate" else high).append(rec)
    return safe, moderate, high, unknown


def _ingredient_score(safe, moderate, high, severe_hits):
    """Safety Trust Score (0-100) from the ratio and severity of flagged items."""
    n_safe, n_mod, n_high = len(safe), len(moderate), len(high)
    total = n_safe + n_mod + n_high
    if total == 0:
        return None
    severity_penalty = min(25 * n_high + 10 * n_mod, 70)
    unsafe_ratio = (n_high + 0.5 * n_mod) / float(total)
    score = 100 - severity_penalty - int(round(unsafe_ratio * 30))
    if n_high >= 1:
        score = min(score, 60)
    if severe_hits:
        score = min(score, 35)
    return max(0, min(100, score))

# --------------------------------------------------------------------------- #
#  Small helpers
# --------------------------------------------------------------------------- #

def utcnow():
    return datetime.now(timezone.utc)


def human_size(num):
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024:
            return "%.0f %s" % (num, unit)
        num /= 1024.0
    return "%.1f GB" % num


def allowed_file(filename, allowed_set):
    return ("." in filename and
            filename.rsplit(".", 1)[1].lower() in allowed_set)


def safe_json(data):
    return json.dumps(data, ensure_ascii=False)


def log_activity(action, detail="", user=None):
    """Write an audit log entry. Never raises."""
    try:
        from models import ActivityLog, db
        entry = ActivityLog(
            user_id=user.id if user else None,
            username=user.email if user else request.remote_addr or "",
            action=action,
            detail=detail[:2000],
            ip=request.remote_addr,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


def notify(user_id, title, message, category="info"):
    """Create a notification. Never raises."""
    try:
        from models import Notification, db
        db.session.add(Notification(user_id=user_id, title=title,
                                    message=message, category=category))
        db.session.commit()
    except Exception:
        db.session.rollback()


def make_result(score, status, risk, summary, reasons, suggestions, meta=None):
    return {
        "score": score,
        "status": status,
        "risk": risk,
        "summary": summary,
        "reasons": reasons,
        "suggestions": suggestions or [],
        "meta": meta or {},
    }


def entry(severity, title, text="", impact=None):
    return {"severity": severity, "title": title, "text": text, "impact": impact}


def risk_for(score):
    if score is None:
        return "unknown"
    if score >= 80:
        return "low"
    if score >= 50:
        return "medium"
    return "high"


# --------------------------------------------------------------------------- #
#  URL inspection
# --------------------------------------------------------------------------- #

def inspect_url(raw_url):
    """Return (is_flag, reason) for a single URL. Deterministic, no network."""
    url = raw_url if "://" in raw_url else "https://" + raw_url
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return True, "Malformed URL"
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    if not host:
        return True, "No valid hostname found"
    if scheme == "http":
        return True, "Unencrypted HTTP link (no HTTPS / SSL)"
    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        return True, "Suspicious top-level domain %s" % tld
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return True, "Link points to a raw IP address instead of a domain"
    if "@" in (parsed.netloc or "") or "@" in parsed.path:
        return True, "Link uses an '@' spoofing trick to hide the real address"
    if host in URL_SHORTENERS:
        return True, "URL shortener hides the real destination domain"
    if any(k in host for k in ("paypal-", "secure-bank", "bank-verify", "login-account")):
        return True, "Domain pattern commonly used by phishing sites"
    if re.match(r"^(bitcoin|litecoin|ethereum):", scheme):
        return True, "Direct cryptocurrency address link"
    return False, "OK"


# --------------------------------------------------------------------------- #
#  Similarity (TF-IDF cosine; sklearn when available, else pure-python)
# --------------------------------------------------------------------------- #

def _tokenize(text):
    return re.findall(r"[a-z0-9]{2,}", text.lower())


# Tokens that add little semantic signal for claim matching. Negation words are
# deliberately kept so "Vaccines do not cause autism" stays distinguishable from
# "Vaccines cause autism".
CLAIM_STOPWORDS = {
    "a", "an", "the", "of", "for", "and", "or", "to", "in", "on", "at", "by",
    "with", "is", "are", "was", "were", "be", "been", "being", "can", "could",
    "will", "would", "should", "may", "might", "do", "does", "did", "have",
    "has", "had", "this", "that", "it", "its", "their", "there", "they",
    "them", "your", "you", "we", "our", "up", "out", "from", "as", "than",
    "then", "when", "while", "which", "who", "whom", "about", "into", "over",
    "after", "before", "between", "under", "very", "also", "just", "every",
    "each", "more", "most", "some", "any", "these", "those", "such", "so",
}


def _claim_tokens(text):
    """Normalised, stopword-stripped tokens that preserve negation words."""
    keep = {"not", "no", "never", "without", "cannot", "dont", "don't",
            "doesn't", "isn't", "aren't", "won't", "can't"}
    return [t for t in re.findall(r"[a-z0-9']+", (text or "").lower())
            if t not in CLAIM_STOPWORDS or t in keep]


def _dice_coeff(a, b):
    """Dice coefficient over token multisets; good at catching paraphrases."""
    if not a or not b:
        return 0.0
    ca, cb = Counter(a), Counter(b)
    overlap = sum((ca & cb).values())
    return 2.0 * overlap / (sum(ca.values()) + sum(cb.values()))


def _jaccard(a, b):
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _cosine_bigram(q, d):
    """Cosine similarity over word bigrams (pure-python TF-IDF substitute)."""
    bq, bd = Counter(zip(q, q[1:])), Counter(zip(d, d[1:]))
    if not bq or not bd:
        return 0.0
    overlap = sum((bq & bd).values())
    return overlap / ((sum(bq.values()) ** 0.5) * (sum(bd.values()) ** 0.5))


def _claim_tfidf(query, documents):
    """TF-IDF cosine with bigrams and sublinear scaling where available."""
    if HAS_SKLEARN:
        try:
            vec = TfidfVectorizer(tokenizer=_tokenize, token_pattern=None,
                                  sublinear_tf=True, use_idf=True,
                                  smooth_idf=True, ngram_range=(1, 2))
            matrix = vec.fit_transform([query] + list(documents))
            q_vec = matrix[0]
            scores = (q_vec * matrix[1:].T).toarray()[0]
            return [float(s) for s in scores]
        except Exception:
            pass
    q = _tokenize(query)
    return [_cosine_bigram(q, _tokenize(d)) for d in documents]


def claim_similarity(claim, docs):
    """
    Combined similarity for the claim checker: TF-IDF (improved) plus token
    Dice and Jaccard overlap. Taking the best of all three lets paraphrased
    claims match a relevant evidence entry instead of falling to a low score.
    """
    q = _claim_tokens(claim)
    tfidf = _claim_tfidf(claim, docs)
    scores = []
    for i, doc in enumerate(docs):
        d = _claim_tokens(doc)
        scores.append(max(tfidf[i], _dice_coeff(q, d), _jaccard(q, d)))
    return scores


def tfidf_similarity(query, documents):
    """Return list of (index, similarity) for query vs documents."""
    if HAS_SKLEARN:
        try:
            vec = TfidfVectorizer(tokenizer=_tokenize, token_pattern=None)
            matrix = vec.fit_transform([query] + list(documents))
            q_vec = matrix[0]
            scores = (q_vec * matrix[1:].T).toarray()[0]
            return [(i, float(scores[i])) for i in range(len(documents))]
        except Exception:
            pass
    # Pure-python fallback (overlapping terms).
    qterms = Counter(_tokenize(query))
    if not qterms:
        return [(i, 0.0) for i in range(len(documents))]
    out = []
    for i, doc in enumerate(documents):
        dterms = Counter(_tokenize(doc))
        overlap = sum(min(qterms[t], dterms[t]) for t in qterms)
        denom = (sum(qterms.values()) + sum(dterms.values())) or 1
        out.append((i, 2.0 * overlap / denom))
    return out


# --------------------------------------------------------------------------- #
#  Text scanner
# --------------------------------------------------------------------------- #

def has_reward_payment_red_flag(text):
    has_pay = any(re.search(r"(?<![a-z0-9])" + w + r"(?![a-z0-9])", text)
                  for w in PAYMENT_WORDS)
    has_reward = any(re.search(r"(?<![a-z0-9])" + w + r"(?![a-z0-9])", text)
                     for w in REWARD_WORDS)
    return has_pay and has_reward


def has_unverified_merchant(text):
    return any(re.search(p, text) for p in UNVERIFIED_MERCHANT_PATTERNS)


def readability(text):
    """Flesch reading ease (approximation). Returns (score, label)."""
    sentences = re.split(r"[.!?]+", text)
    sentences = [s for s in sentences if s.strip()]
    words = re.findall(r"[A-Za-z']+", text)
    if not sentences or not words:
        return None, "not enough text"
    syllables = sum(_syllables(w) for w in words)
    wps = len(words) / len(sentences)
    spw = syllables / max(len(words), 1)
    score = 206.835 - 1.015 * wps - 84.6 * spw
    score = max(0.0, min(100.0, score))
    if score >= 60:
        label = "easy to read"
    elif score >= 40:
        label = "moderately easy"
    else:
        label = "complex"
    return round(score, 1), label


def _syllables(word):
    word = word.lower()
    count = 0
    vowels = "aeiouy"
    prev = None
    for ch in word:
        if ch in vowels:
            if ch != prev:
                count += 1
        prev = ch
    if word.endswith("e"):
        count -= 1
    return max(1, count)


def ai_text_probability(text):
    """
    Statistical heuristic (0-100) estimating the chance text was machine-
    generated: low burstiness, uniform sentence lengths and heavy repetition
    correlate with generated prose. This is an approximation, not a detector.
    """
    sentences = [s for s in re.split(r"[.!?]+", text) if len(s.strip()) > 2]
    if len(sentences) < 3:
        return 25
    lengths = [len(re.findall(r"[A-Za-z']+", s)) for s in sentences]
    mean = (sum(lengths) / len(lengths)) or 1
    variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
    cv = (variance ** 0.5) / mean  # coefficient of variation (burstiness)

    tokens = re.findall(r"[a-z']+", text.lower())
    total = len(tokens) or 1
    uniq = len(set(tokens))
    diversity = uniq / total  # type-token ratio

    bigrams = Counter(zip(tokens, tokens[1:]))
    top_share = (bigrams.most_common(1)[0][1] / max(total - 1, 1)) if bigrams else 0

    prob = 50.0
    prob += (0.35 - min(cv, 1.5)) * 40.0     # low burstiness -> AI-ish
    prob += max(0.0, 0.78 - diversity) * 60.0  # low diversity -> repetitive
    prob -= max(0.0, diversity - 0.62) * 40.0
    prob += max(0.0, top_share - 0.06) * 200.0  # heavy n-gram repetition
    return int(max(0, min(100, prob)))


def find_matches(lower, keywords):
    """Return keyword hits respecting word boundaries (case-insensitive)."""
    return [k for k in keywords
            if re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", lower)]


def text_scanner(content, scan_type="Text / Email / Message"):
    """
    Full evidence-based text analysis. Returns a make_result() dict.
    Empty/insufficient input -> status 'insufficient', score None.
    """
    text = (content or "").strip()
    if not text:
        return make_result(None, "insufficient", "unknown",
                           "No text content was provided, so there is insufficient evidence to score.",
                           [entry("info", "Insufficient evidence",
                                  "Nothing was submitted for analysis.")],
                           ["Paste the full message or document you want to verify."])

    reasons, suggestions = [], []
    score = 100
    lower = text.lower()
    scam_summary = None
    scam_signals = {}

    if len(text) < 20:
        return make_result(None, "insufficient", "unknown",
                           "The submitted text is too short to analyse reliably.",
                           [entry("info", "Insufficient evidence",
                                  "Input is under 20 characters. Longer content produces a more reliable score.")],
                           ["Provide the full message, email or document."])

    # 1. High-pressure language -------------------------------------------------
    found = [k for k in HIGH_PRESSURE_KEYWORDS
             if re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", lower)]
    if found:
        penalty = 15 * len(found)
        score -= penalty
        shown = ", ".join("“%s”" % k for k in found[:8])
        if len(found) > 8:
            shown += " (+%d more)" % (len(found) - 8)
        reasons.append(entry("danger", "High-pressure language detected",
                             "Urgency/prize trigger phrases: %s." % shown,
                             "−%d points" % penalty))
    else:
        reasons.append(entry("success", "No high-pressure language",
                             "No urgency or deadline-pressure phrases detected."))

    # 2. Links -------------------------------------------------------------------
    urls = re.findall(r"(?:https?://|www\.)[^\s<>\"'\]\)]+", text)
    flagged = [(u, r) for u, (is_f, r) in [(u, inspect_url(u)) for u in urls] if is_f]
    if flagged:
        score -= 25
        reasons.append(entry("danger", "Insecure or suspicious link detected",
                             "; ".join("%s → %s" % (u, r) for u, r in flagged[:5]),
                             "−25 points"))
    elif urls:
        reasons.append(entry("success", "%d link(s) inspected" % len(urls),
                             "All links use HTTPS with common trusted domains."))
    else:
        reasons.append(entry("info", "No links present",
                             "No URLs were found to inspect."))

    # 3. Payment / reward & merchant --------------------------------------------
    red = []
    if has_reward_payment_red_flag(lower):
        red.append("asks you to pay money to receive a reward/prize")
    if has_unverified_merchant(lower):
        red.append("references an unverified merchant / payment collector")
    if red:
        score -= 30
        reasons.append(entry("danger", "Payment-to-reward scam pattern",
                             "This content " + "; ".join(red) + ".", "−30 points"))
    else:
        reasons.append(entry("success", "No payment scam pattern",
                             "No pay-to-receive-reward or unverified-merchant signals found."))

    # 3b. Prize / lottery / financial lure ----------------------------------------
    prize_hits = find_matches(lower, PRIZE_LURE_KEYWORDS)
    if prize_hits:
        penalty = min(25 * len(prize_hits), 50)
        score -= penalty
        reasons.append(entry("danger", "Prize / lottery lure detected",
                             "Financial-incentive trigger phrases: %s."
                             % ", ".join("“%s”" % p for p in prize_hits[:6]),
                             "−%d points" % penalty))
    else:
        reasons.append(entry("success", "No prize / lottery lure",
                             "No financial-incentive trigger phrases detected."))

    # 3c. Credential / OTP harvesting request --------------------------------------
    cred_hits = find_matches(lower, CREDENTIAL_REQUEST_KEYWORDS)
    if cred_hits:
        penalty = min(25 * len(cred_hits), 50)
        score -= penalty
        reasons.append(entry("danger", "Credential / OTP harvesting request",
                             "The content asks for sensitive data: %s."
                             % ", ".join("“%s”" % p for p in cred_hits[:6]),
                             "−%d points" % penalty))
    else:
        reasons.append(entry("success", "No credential requests",
                             "No request for OTPs, PINs or passwords detected."))

    # 3d. Combined financial-scam patterns ------------------------------------------
    money_hits = find_matches(lower, MONEY_TERMS)
    if prize_hits and cred_hits:
        score -= 30
        scam_summary = ("High-risk scam pattern: a financial reward lure is combined with a "
                        "request for an OTP, PIN or password - the classic credential-harvesting "
                        "scam. Never share codes, PINs or passwords.")
        scam_signals["lure"] = prize_hits[:6]
        scam_signals["credentials"] = cred_hits[:6]
        reasons.append(entry("danger", "Prize + OTP scam pattern",
                             "A reward/prize lure combined with a request for an OTP, PIN or "
                             "password matches the most common credential-harvesting scam.",
                             "−30 points"))
    elif prize_hits and money_hits:
        score -= 25
        scam_summary = ("Fake-winnings / advance-fee pattern: a prize lure is combined with "
                        "money terms. Legitimate prizes never require fees or payments.")
        scam_signals["lure"] = prize_hits[:6]
        scam_signals["money"] = money_hits[:6]
        reasons.append(entry("danger", "Fake-winnings / advance-fee pattern",
                             "A prize lure combined with money terminology - the classic "
                             "“you won, now pay or verify” scam.", "−25 points"))
    elif cred_hits and money_hits:
        score -= 20
        scam_summary = ("Suspicious money + credential request: the content discusses money "
                        "while asking for OTPs, PINs or passwords.")
        scam_signals["credentials"] = cred_hits[:6]
        scam_signals["money"] = money_hits[:6]
        reasons.append(entry("warning", "Money + credential request",
                             "Money terminology combined with a request for OTP/PIN/password.",
                             "−20 points"))

    # 4. Sender email domain ------------------------------------------------------
    hosts = set(re.findall(r"(?<![\w.])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)", lower))
    if hosts:
        free = [h for h in hosts if h in FREE_MAIL_DOMAINS]
        if free:
            score -= 5
            reasons.append(entry("warning", "Free-mail sender domain",
                                 "Addresses on %s - legitimate organisations rarely use these for official communication."
                                 % ", ".join(sorted(free)), "−5 points"))
        else:
            reasons.append(entry("success", "Sender domain looks professional",
                                 "Email domains found: %s." % ", ".join(sorted(hosts))))

    # 5. Spam / scam corpus similarity --------------------------------------------
    sims = tfidf_similarity(text, SCAM_CORPUS)
    best = max(sims, key=lambda x: x[1])
    if best[1] >= 0.45:
        score -= 15
        reasons.append(entry("warning", "Similar to known scam patterns",
                             "The text shares %.0f%% similarity with documented scam messages."
                             % (best[1] * 100), "−15 points"))
    elif best[1] >= 0.3:
        reasons.append(entry("info", "Some overlap with scam patterns",
                             "Moderate similarity (%.0f%%) to known scams - not conclusive."
                             % (best[1] * 100)))
    else:
        reasons.append(entry("success", "Low similarity to known scams",
                             "The content does not resemble documented scam messages."))

    # 6. Grammar quality ------------------------------------------------------------
    issues = []
    for pat, label in GRAMMAR_ISSUES:
        if re.search(pat, lower):
            issues.append(label)
    if issues:
        score -= 5
        reasons.append(entry("warning", "Grammar issues detected",
                             "Possible %s." % ", ".join(issues), "−5 points"))
    else:
        reasons.append(entry("success", "Grammar looks clean",
                             "No common grammatical error patterns found."))

    # 7. AI-generated text heuristic (informational) -------------------------------
    ai_prob = ai_text_probability(text)
    if ai_prob >= 70:
        score -= 10
        reasons.append(entry("warning", "Possible AI-generated text",
                             "Statistical heuristic gives a %d%% probability of machine-generated prose "
                             "(low variation, high repetition)." % ai_prob, "−10 points"))
    else:
        reasons.append(entry("info", "AI-generation heuristic",
                             "Statistical probability of AI-generated text: %d%%." % ai_prob))

    # 8. Readability ------------------------------------------------------------------
    read, read_label = readability(text)
    if read is not None:
        reasons.append(entry("info", "Readability",
                             "Flesch reading ease %.1f (%s)." % (read, read_label)))

    # 9. Profile ----------------------------------------------------------------------
    reasons.append(entry("info", "Content profile",
                         "%d characters, %d words." % (len(text), len(text.split()))))

    score = max(0, min(100, score))

    # 10. Short-content honesty gate ------------------------------------------------
    # Never present a high score as "trustworthy" based on very little text.
    if score >= 80 and len(text) < SHORT_TEXT_LIMIT:
        status, risk, score = "insufficient", "unknown", None
        reasons.append(entry("info", "Not enough content to confirm trustworthiness",
                             "This short input produced no risk signals, but there is too "
                             "little text to justify a high trust score. Longer content "
                             "enables a confident verdict."))
        suggestions.append("Provide the full message or document for a reliable verdict.")
    else:
        status, risk = "verified", risk_for(score)

    if scam_summary:
        summary = scam_summary
    else:
        summary = "Text analysis complete: %d evidence checks ran against the submitted content." % len(reasons)
    if not suggestions:
        suggestions = advice_for_score(score) if score is not None else \
            ["Provide more content so the verification can reach a confident verdict."]

    meta = {"type": scan_type, "length": len(text), "words": len(text.split())}
    if scam_signals:
        meta["scam_signals"] = {k: v for k, v in scam_signals.items()}
    return make_result(score, status, risk, summary, reasons, suggestions, meta)


def advice_for_score(score):
    if score >= 80:
        return ["No significant red flags - but always verify the sender through an official channel before sharing sensitive data."]
    if score >= 50:
        return ["Never share OTPs, passwords or bank details.",
                "Verify through the organisation's official app/website, not links in the message.",
                "Never pay a fee to receive an offer, refund, prize or inheritance."]
    return ["Do not respond, click links, or send money.",
            "Report to your bank and the cyber-crime helpline (India: 1930).",
            "Keep the message and sender details as evidence."]


# --------------------------------------------------------------------------- #
#  Image scanner (payment screenshots, QR codes, reverse-image analysis)
# --------------------------------------------------------------------------- #

# --- Digital payment receipt structural verification ------------------------ #
# Fake / template Paytm-UPI receipts reuse placeholder identifiers: generic
# phone numbers (e.g. 9012348882), repeating/sequential digits, letter-O IFSC
# codes and template branch codes. These structural checks run on the OCR text
# and QR payload BEFORE generic text rules are applied. A confirmed match
# overrides the score with a High Risk / Potential Fake Receipt verdict.

RECEIPT_CONTEXT_KEYWORDS = [
    "transaction", "upi", "ifsc", "paytm", "google pay", "gpay", "phonepe",
    "bharatpe", "bhim", "order id", "ref id", "reference id", "txn",
    "utr", "receipt", "payment successful", "paid", "received", "amount",
    "beneficiary", "collect request",
]

UPI_HANDLES = {
    "paytm", "upi", "ybl", "okaxis", "okhdfcbank", "okicici", "oksbi",
    "okboi", "okpunjab", "okcc", "okab", "kkb", "icici", "sbi",
    "hdfcbank", "pnb", "axl", "kotak", "yesbank", "aubank", "idfc",
    "rbl", "unionbank", "canarabank", "bobbank", "barodapay", "fbl",
    "aiobank", "kpay", "pb", "mahb", "dlhb", "nyara", "jupiter", "axisb",
}

# Phone numbers used as placeholders in demo / fake payment screenshots.
PLACEHOLDER_UPI_IDENTIFIERS = {
    "9012348882", "9012345678", "9876543210", "1234567890",
    "1111111111", "2222222222", "3333333333", "4444444444",
    "5555555555", "6666666666", "7777777777", "8888888888",
    "9999999999", "0000000000",
}

PLACEHOLDER_UPI_LABELS = {
    "payee", "beneficiary", "merchant", "test", "sample", "demo",
    "testupi", "sampleupi", "abc", "abcd", "xyz", "user",
}

PLACEHOLDER_IFSC_PREFIXES = ("abcd", "aaaa", "xxxx", "zzzz", "test", "demo",
                             "ifsx", "ifsc")

IFSC_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]{4}[0-9Oo][A-Za-z0-9]{6}(?![A-Za-z0-9])")
UPI_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9._-]{2,}@[A-Za-z0-9.-]{2,}(?![A-Za-z0-9])")

# --- UPI payment QR verification ------------------------------------------ #
# UPI deep links follow the standard scheme "upi://pay?<query>". The mandatory
# field is pa (payee address); pn/am/tn/cu are optional but common.
UPI_QR_SCHEME_RE = re.compile(r"^upi://pay[/?]?", re.IGNORECASE)

# Strict UPI ID: local-part (2+ chars of [A-Za-z0-9._-]) @ handle (a PSP
# identifier made of letters/digits, dots or hyphens). Rejects bare phone
# numbers without a handle, spaces, and @-less strings.
UPI_ID_STRICT_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,48})?@[A-Za-z0-9](?:[A-Za-z0-9.-]{1,63})$")

# Wording in the transaction note (tn) that signals a scam-style payment QR.
UPI_SUSPICIOUS_NOTE_KEYWORDS = [
    "reward", "prize", "lottery", "winnings", "unlock", "processing fee",
    "fee to release", "release fee", "security deposit", "registration fee",
    "cashback", "gift card", "coupon", "refund", "claim",
]


def _flag_ifsc(token):
    """Return (severity, reason) when an IFSC token is placeholder/invalid."""
    m = re.fullmatch(r"[A-Za-z]{4}([0-9Oo])([A-Za-z0-9]{6})", token)
    if not m:
        return None
    pos5, tail = m.group(1), m.group(2)
    if pos5 in "Oo":
        return "danger", ("IFSC '%s' uses the letter O where the digit 0 is "
                          "required - no bank issues this code." % token)
    if token[:4].lower() in PLACEHOLDER_IFSC_PREFIXES:
        return "danger", ("IFSC '%s' uses the generic/template bank prefix '%s'."
                          % (token, token[:4]))
    if not re.fullmatch(r"\d{6}", tail):
        return "warning", ("IFSC '%s' has a non-numeric branch code (RBI format "
                           "requires 6 digits)." % token)
    if len(set(tail)) == 1 or tail in ("012345", "123456", "654321"):
        return "danger", ("IFSC '%s' has the placeholder branch code '%s' typical "
                          "of template receipts." % (token, tail))
    return None


def _flag_upi(upi):
    """Return (severity, reason) when a UPI ID is placeholder/generic."""
    identifier, _, handle = upi.partition("@")
    ident = identifier.lower()
    if handle.lower() not in UPI_HANDLES:
        return None
    if ident in PLACEHOLDER_UPI_IDENTIFIERS:
        return "danger", ("UPI ID '%s' matches the template phone number used in "
                          "demo/fake receipts - real receipts never show it." % upi)
    if len(ident) >= 8 and re.fullmatch(r"\d{8,}", ident):
        if re.fullmatch(r"(\d)\1{7,}", ident):
            return "danger", ("UPI ID '%s' is a repeating-digit placeholder (all "
                              "'%s')." % (upi, ident[0]))
        if re.fullmatch(r"0*1234567890?|0*9876543210?", ident):
            return "danger", "UPI ID '%s' is a sequential placeholder number." % upi
    if ident in PLACEHOLDER_UPI_LABELS:
        return "danger", "UPI ID '%s' is a generic placeholder label." % upi
    return None


def _inspect_receipt(ocr_text, qr_payload=None, filename=""):
    """
    Strict structural verification of digital payment receipts (Paytm/UPI).
    Returns (entries, summary) where summary is the High Risk / Potential Fake
    Receipt verdict when placeholder or structurally invalid identifiers are
    found in the extracted text / QR payload / filename.
    """
    combined = re.sub(r"\s*@\s*", "@",
                      " ".join([ocr_text or "", qr_payload or "", filename or ""])).lower()
    if not any(k in combined for k in RECEIPT_CONTEXT_KEYWORDS):
        return [], None
    entries, flags = [], []
    ifsc_tokens = list(dict.fromkeys(IFSC_TOKEN_RE.findall(combined)))
    for tok in ifsc_tokens:
        flag = _flag_ifsc(tok)
        if flag:
            entries.append(entry(flag[0], "Suspicious IFSC code", flag[1],
                                 "receipt identifier validation failed"))
            flags.append(flag[1])
    upi_ids = [u for u in dict.fromkeys(UPI_ID_RE.findall(combined))
               if u.partition("@")[2].lower() in UPI_HANDLES]
    for upi in upi_ids:
        flag = _flag_upi(upi)
        if flag:
            entries.append(entry(flag[0], "Suspicious UPI ID", flag[1],
                                 "receipt identifier validation failed"))
            flags.append(flag[1])
    if flags:
        return entries, ("High Risk / Potential Fake Receipt - %d structurally "
                         "invalid or placeholder identifier(s) were found in the "
                         "receipt." % len(flags))
    if ifsc_tokens or upi_ids:
        entries.append(entry("success", "Receipt identifiers structurally valid",
                             "Found %d IFSC and %d UPI identifier(s); all passed "
                             "structural checks." % (len(ifsc_tokens), len(upi_ids))))
    return entries, None


def _get_ocr_reader():
    global _EASYOCR_READER
    if _EASYOCR_READER is None and HAS_EASYOCR and current_app.config.get("ENABLE_OCR", True):
        try:
            _EASYOCR_READER = easyocr.Reader(current_app.config.get("OCR_LANGUAGES", ["en"]),
                                             gpu=False, verbose=False)
        except Exception:
            _EASYOCR_READER = False
    return _EASYOCR_READER


def _preprocess_for_ocr(image_path):
    """Return a list of up to two OCR-ready image arrays, or None.

    Pipeline tuned for shiny plastic, curved packaging, shadows and condensed
    label text:
      1) grayscale conversion
      2) upscale by 2x (capped so large uploads stay tractable)
      3) unsharp-mask contrast sharpening
      4) CLAHE contrast equalisation
      5) adaptive-threshold binary variant (recovers strong text/line edges)
    """
    img = None
    if HAS_CV2:
        try:
            img = cv2.imread(image_path)
        except Exception:
            img = None
    if img is None and HAS_PIL and HAS_NUMPY:
        try:
            img = np.array(Image.open(image_path).convert("RGB"))
        except Exception:
            img = None
    if img is None:
        return None
    if not (HAS_CV2 and HAS_NUMPY):
        if HAS_PIL and HAS_NUMPY:
            try:
                from PIL import ImageOps
                return [np.array(ImageOps.autocontrast(Image.fromarray(img).convert("L")))]
            except Exception:
                return None
        return None
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        h, w = gray.shape[:2]
        if min(h, w) < 1600:
            scale = 2.0
            gray = cv2.resize(gray, (int(w * scale), int(h * scale)),
                              interpolation=cv2.INTER_CUBIC)
        blur = cv2.GaussianBlur(gray, (0, 0), 1.0)
        sharp = cv2.addWeighted(gray, 1.6, blur, -0.6, 0)
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(sharp)
        binary = cv2.adaptiveThreshold(enhanced, 255,
                                       cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                       cv2.THRESH_BINARY, 31, 10)
        return [enhanced, binary]
    except Exception:
        return None


def _ocr_text_from(reader, target):
    """Run OCR on one target; return (text, mean_conf) or (None, 0.0)."""
    result = reader.readtext(target, detail=1, paragraph=False)
    parts, confs = [], []
    for (_bbox, txt, conf) in result:
        parts.append(txt)
        confs.append(float(conf))
    text = "\n".join(parts).strip()
    mean_conf = (sum(confs) / len(confs)) if confs else 0.0
    return (text or None), mean_conf


def extract_text_ocr(image_path):
    """Return (text, mean_confidence) or (None, None) if OCR unavailable/failed.

    Tries each preprocessed candidate (enhanced grayscale, adaptive-threshold
    binary) and finally the raw file, keeping the pass that recovered the most
    characters. Newlines are preserved so line-based header/region logic works.
    """
    reader = _get_ocr_reader()
    if not reader:
        return None, None
    candidates = list(_preprocess_for_ocr(image_path) or []) + [image_path]
    best, best_conf, best_len = None, 0.0, 0
    for cand in candidates:
        try:
            text, conf = _ocr_text_from(reader, cand)
        except Exception:
            continue
        if not text:
            continue
        n = len(text)
        if n > best_len:
            best, best_conf, best_len = text, conf, n
    if best is None:
        return None, None
    return best, round(best_conf, 3)


def _dhash(img_gray, size=16):
    if not HAS_NUMPY:
        return None
    try:
        small = cv2.resize(img_gray, (size + 1, size))
        diff = small[:, 1:] > small[:, :-1]
        return diff.flatten().tobytes().hex()
    except Exception:
        return None


def image_scanner(filepath, filename=""):
    """
    Real image analysis: OCR + metadata + brightness/blur/noise/compression/
    screenshot/tampering(ELA)/duplicate hash/QR decode. Score reflects the
    actual metrics measured.
    """
    reasons, suggestions = [], []
    score = 100

    if not HAS_PIL:
        return make_result(None, "error", "unknown",
                           "Image analysis library unavailable.",
                           [entry("danger", "Analysis unavailable", "Pillow is not installed.")],
                           ["Install requirements and retry."])

    try:
        img_pil = Image.open(filepath)
        img_pil.load()
    except Exception:
        return make_result(None, "error", "unknown",
                           "The uploaded file could not be opened as an image.",
                           [entry("danger", "Invalid image file", "Could not decode image data.")],
                           ["Upload a valid PNG, JPG, JPEG, WEBP, GIF, BMP or TIFF."])

    fmt = (img_pil.format or "UNKNOWN").upper()
    width, height = img_pil.size
    size_label = human_size(os.path.getsize(filepath))
    reasons.append(entry("success", "Valid image verified",
                         "%s image, %dx%d px, %s on disk." % (fmt, width, height, size_label)))

    # --- Metadata consistency -------------------------------------------------------
    meta_signals = []
    exif = img_pil.getexif()
    for tag_id, value in exif.items():
        tag = EXIF_TAGS.get(tag_id, "")
        if tag in ("Software", "ImageDescription", "Copyright", "Artist", "Comment", "XPComment"):
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", "ignore")
                except Exception:
                    value = str(value)
            if isinstance(value, str) and value.strip():
                meta_signals.append("%s=%s" % (tag, value[:60]))
    editor_tools = ("photoshop", "canva", "picsart", "gimp", "snapseed", "pixelmator")
    lower_meta = " ".join(meta_signals).lower()
    if any(t in lower_meta for t in editor_tools) and ("screenshot" in lower_meta or "compression" in lower_meta):
        score -= 15
        reasons.append(entry("warning", "Editing software in metadata",
                             "Metadata reports editing tools: %s." % "; ".join(meta_signals[:3]),
                             "−15 points"))
    elif meta_signals:
        reasons.append(entry("info", "Metadata present",
                             "; ".join(meta_signals[:4])))

    # --- Pixel-level metrics (OpenCV) ------------------------------------------------
    dhash = None
    if HAS_CV2:
        gray = cv2.imread(filepath, cv2.IMREAD_GRAYSCALE)
        if gray is not None and gray.size:
            brightness = float(np.mean(gray)) if HAS_NUMPY else None
            laplacian = cv2.Laplacian(gray, cv2.CV_64F)
            blur_var = float(laplacian.var())
            noise_est = float(laplacian.std()) if HAS_NUMPY else None

            if brightness is not None and (brightness < 35 or brightness > 235):
                score -= 10
                reasons.append(entry("warning", "Extreme brightness level",
                                     "Mean brightness %.0f/255 - image may be too dark/bright to trust details."
                                     % brightness, "−10 points"))
            else:
                reasons.append(entry("success", "Exposure looks normal",
                                     "Mean brightness %d/255." % (brightness or 0)))

            if blur_var < 60:
                score -= 15
                reasons.append(entry("warning", "Blur detected",
                                     "Laplacian variance %.1f indicates a blurry image." % blur_var,
                                     "−15 points"))
            elif blur_var < 120:
                reasons.append(entry("info", "Slightly soft focus",
                                     "Laplacian variance %.1f." % blur_var))
            else:
                reasons.append(entry("success", "Sharpness is good",
                                     "Laplacian variance %.1f - image is in focus." % blur_var))

            # Compression / screenshot indicators ------------------------------------
            try:
                buf = io.BytesIO()
                img_pil.convert("RGB").save(buf, format="JPEG", quality=85)
                buf.seek(0)
                recomp = cv2.imdecode(np.frombuffer(buf.getvalue(), np.uint8),
                                      cv2.IMREAD_GRAYSCALE)
                if recomp is not None and gray.shape == recomp.shape:
                    psnr = cv2.PSNR(gray, recomp)
                    if psnr < 28:
                        score -= 10
                        reasons.append(entry("warning", "Heavy compression artifacts",
                                             "PSNR %.1f dB - likely re-compressed or screenshot-saved content."
                                             % psnr, "−10 points"))
                    else:
                        reasons.append(entry("success", "Low compression artifacts",
                                             "PSNR %.1f dB between original and re-encode." % psnr))
            except Exception:
                pass

            # Screenshot detection (uniform regions + strong text edges) -------------
            try:
                small = cv2.resize(gray, (120, 120))
                edges = cv2.Canny(small, 80, 200)
                edge_density = float(np.mean(edges > 0))
                unique = len(np.unique(small)) / (120 * 120)
                screenshot_hint = edge_density > 0.12 and unique < 0.45
                if screenshot_hint:
                    score -= 10
                    reasons.append(entry("warning", "Screenshot-like pattern",
                                         "High text-edge density with low color diversity - typical of screenshots.",
                                         "−10 points"))
            except Exception:
                pass

            # Tampering detection (Error Level Analysis) -------------------------------
            try:
                buf2 = io.BytesIO()
                img_pil.convert("RGB").save(buf2, format="JPEG", quality=90)
                buf2.seek(0)
                q90 = cv2.imdecode(np.frombuffer(buf2.getvalue(), np.uint8), cv2.IMREAD_GRAYSCALE)
                q90 = cv2.resize(q90, (gray.shape[1], gray.shape[0]))
                ela = cv2.absdiff(gray, q90)
                ela_mean = float(np.mean(ela))
                if ela_mean > 12:
                    score -= 20
                    reasons.append(entry("danger", "Possible image tampering",
                                         "Error-Level Analysis shows inconsistent regions "
                                         "(ELA score %.1f) - areas may have been edited." % ela_mean,
                                         "−20 points"))
                else:
                    reasons.append(entry("success", "No tampering detected via ELA",
                                         "Re-compression error is uniform (ELA %.1f)." % ela_mean))
            except Exception:
                pass

            # Perceptual hash for duplicate detection -----------------------------------
            dhash = _dhash(gray)
            if dhash:
                reasons.append(entry("info", "Perceptual fingerprint", "dHash %s" % dhash[:24] + "..."))
                score = min(score, _check_duplicates(dhash, reasons))
        else:
            reasons.append(entry("warning", "Image could not be read for pixel analysis",
                                 "OpenCV failed to decode the file."))

    # --- QR decode ----------------------------------------------------------------------
    qr_payload = None
    qr_payload, qr_method, _ = _decode_qr_robust(filepath)
    if qr_payload:
        reasons.append(entry("success", "QR code decoded",
                             "Payload extracted via %s for scoring: %s"
                             % (qr_method, qr_payload[:80])))

    # --- OCR -----------------------------------------------------------------------------
    ocr_text, ocr_conf = extract_text_ocr(filepath)
    if ocr_text:
        reasons.append(entry("success", "OCR extraction succeeded",
                             "Extracted %d characters with mean confidence %.2f."
                             % (len(ocr_text), ocr_conf or 0)))
        if ocr_conf is not None and ocr_conf < 0.5:
            score -= 10
            reasons.append(entry("warning", "Low OCR confidence",
                                 "Mean OCR confidence %.2f - text may be illegible." % ocr_conf,
                                 "−10 points"))
        # Run the text rules on the extracted content.
        t = text_scanner(ocr_text, scan_type="Extracted image text")
        for r in t["reasons"]:
            if r["severity"] in ("danger", "warning"):
                reasons.append(r)
        if t["score"] is not None:
            score = min(score, t["score"])
    else:
        reasons.append(entry("info", "OCR unavailable",
                             "On-screen text could not be extracted (OCR disabled or failed). "
                             "Score is based on image-level signals only."))

    # --- Digital payment receipt structural verification --------------------------------
    # Runs on the extracted text / QR payload / filename. A confirmed placeholder or
    # structurally invalid identifier caps the score at 10 (High Risk) and overrides
    # the summary with a Potential Fake Receipt verdict.
    receipt_entries, fake_receipt_hint = _inspect_receipt(ocr_text, qr_payload, filename)
    reasons.extend(receipt_entries)
    if fake_receipt_hint:
        score = min(score, 10)
        receipt_verdict = "failed"
    elif receipt_entries:
        receipt_verdict = "passed"
    else:
        receipt_verdict = "not-a-receipt"

    # --- Payment/QR filename & reward pattern ----------------------------------------------
    lower_name = filename.lower()
    if any(k in lower_name for k in ("payment", "receipt", "qr", "upi", "transaction", "invoice")):
        reasons.append(entry("info", "Payment / QR related upload",
                             "Filename suggests %s content." % lower_name))
    if qr_payload:
        if has_reward_payment_red_flag(qr_payload.lower()) or has_unverified_merchant(qr_payload.lower()):
            score -= 30
            reasons.append(entry("danger", "Suspicious QR payload",
                                 "The QR code leads to payment-to-reward or unverified-merchant content.",
                                 "−30 points"))

    score = max(0, min(100, score))
    summary = fake_receipt_hint or ("Image analysis: OCR, metadata, sharpness, compression, "
                                    "tampering and duplicate checks completed.")
    return make_result(score, "verified", risk_for(score),
                       summary, reasons, advice_for_score(score),
                       {"type": "Image", "format": fmt, "size": "%dx%d" % (width, height),
                        "ocr_confidence": ocr_conf, "ocr_text": (ocr_text or "")[:4000],
                        "dhash": dhash, "receipt_verification": receipt_verdict})


def _check_duplicates(dhash, reasons):
    """Compare a perceptual hash against recent scans in the DB."""
    score = 100
    try:
        from models import ScanRecord, db
        recent = ScanRecord.query.filter(ScanRecord.meta_json.isnot(None)) \
            .order_by(ScanRecord.id.desc()).limit(20).all()
        for rec in recent:
            try:
                meta = json.loads(rec.meta_json or "{}")
            except Exception:
                continue
            if isinstance(meta, dict) and meta.get("dhash") == dhash and meta.get("type") == "Image":
                score -= 20
                reasons.append(entry("warning", "Duplicate image detected",
                                     "Visually identical content was analysed before (scan #%d)." % rec.id,
                                     "−20 points"))
                break
    except Exception:
        pass
    return score


# --------------------------------------------------------------------------- #
#  Website scanner
# --------------------------------------------------------------------------- #

def _safe_request(url, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0 (TrustLens-Verifier/1.0)",
        }, allow_redirects=True)
        return r
    except Exception:
        return None


def website_scanner(raw_url):
    reasons, suggestions = [], []
    if not raw_url.strip():
        return make_result(None, "insufficient", "unknown",
                           "No URL was provided.",
                           [entry("info", "Insufficient evidence", "Enter a website URL to verify.")],
                           ["Enter a full URL such as https://example.com"])
    url = raw_url if "://" in raw_url else "https://" + raw_url
    score = 100

    # 1. Static URL-pattern checks (always run, deterministic) ----------------------
    is_flag, reason = inspect_url(url)
    if is_flag:
        score -= 25
        reasons.append(entry("danger", "Suspicious URL pattern", reason, "−25 points"))
    else:
        reasons.append(entry("success", "URL structure looks normal",
                             "HTTPS scheme and common top-level domain."))

    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    # Homograph / punycode detection
    if "xn--" in host or re.search(r"[^\x00-\x7f]", host):
        score -= 20
        reasons.append(entry("danger", "Homograph / punycode domain",
                             "The domain contains look-alike (non-ASCII or punycode) characters.", "−20 points"))
    # Suspicious keywords in path
    path_kw = [k for k in SUSPICIOUS_URL_KEYWORDS if k in (parsed.path + parsed.query).lower()]
    if path_kw:
        score -= 10
        reasons.append(entry("warning", "Phishing keywords in URL",
                             "Found: %s." % ", ".join(path_kw[:5]), "−10 points"))

    # 2. WHOIS (domain age) ------------------------------------------------------------
    domain_age = None
    if HAS_WHOIS and current_app.config.get("LIVE_NETWORK", True):
        try:
            w = pywhois.whois(host)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                domain_age = (datetime.now(created.tzinfo) - created).days
                if domain_age < 30:
                    score -= 20
                    reasons.append(entry("warning", "Domain is brand new",
                                         "Registered only %d days ago - a common trait of throwaway scam sites."
                                         % domain_age, "−20 points"))
                elif domain_age < 365:
                    reasons.append(entry("info", "Young domain",
                                         "Registered %d days ago." % domain_age))
                else:
                    reasons.append(entry("success", "Established domain",
                                         "Registered %d days ago." % domain_age))
            org = getattr(w, "org", None) or getattr(w, "registrar", None)
            if org:
                reasons.append(entry("info", "WHOIS registrant", str(org)[:80]))
        except Exception:
            reasons.append(entry("info", "WHOIS unavailable",
                                 "Registration data could not be retrieved (network or registry limits)."))

    # 3. Live connectivity / TLS / redirects ----------------------------------------------
    live = current_app.config.get("LIVE_NETWORK", True)
    if live and HAS_REQUESTS:
        resp = _safe_request(url)
        if resp is None:
            score -= 15
            reasons.append(entry("warning", "Website unreachable",
                                 "The server did not respond within the timeout.", "−15 points"))
        else:
            chain = [h.url for h in resp.history] + [resp.url]
            if len(resp.history) > 2:
                score -= 10
                reasons.append(entry("warning", "Long redirect chain",
                                     "%d redirects - commonly used to hide the final destination."
                                     % len(resp.history), "−10 points"))
            else:
                reasons.append(entry("success", "Redirect chain is short",
                                     "Final URL: %s" % resp.url[:100]))
            if resp.url.startswith("https://"):
                reasons.append(entry("success", "TLS active", "Connection is encrypted (HTTPS)."))
            title = ""
            if HAS_BS4:
                soup = BeautifulSoup(resp.text[:200000], "html.parser")
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()
                    reasons.append(entry("info", "Page title", title[:100]))
                if not title:
                    score -= 5
                    reasons.append(entry("warning", "No page title",
                                         "The page returned no meaningful <title>.", "−5 points"))
    elif not live:
        reasons.append(entry("info", "Live verification disabled",
                             "Network checks are disabled in this configuration; score is based on URL patterns only."))
    else:
        reasons.append(entry("info", "Live verification unavailable",
                             "The requests library is not installed; score is based on URL patterns only."))

    score = max(0, min(100, score))
    return make_result(score, "verified", risk_for(score),
                       "Website analysis: URL patterns, domain age, TLS and redirect behaviour checked.",
                       reasons, ["Prefer https:// and verify the exact domain spelling.",
                                 "Check WHOIS and contact details before sharing data."],
                       {"type": "Website", "url": url, "domain": host})


# --------------------------------------------------------------------------- #
#  Job / internship scanner
# --------------------------------------------------------------------------- #

def extract_pdf_text(path):
    if not HAS_PYPDF:
        return None
    try:
        reader = pypdf.PdfReader(path)
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception:
        return None


def job_scanner(url="", text="", file_path=None, file_name=""):
    reasons, suggestions = [], []
    score = 100
    content_parts = []
    substantive_parts = []

    if file_path:
        ext = (file_name.rsplit(".", 1)[-1] or "").lower()
        if ext == "pdf":
            pdf_text = extract_pdf_text(file_path)
            if pdf_text:
                content_parts.append(pdf_text)
                substantive_parts.append(pdf_text)
                reasons.append(entry("success", "Offer letter parsed",
                                     "Extracted %d characters from the PDF." % len(pdf_text)))
            else:
                return make_result(None, "insufficient", "unknown",
                                   "The PDF could not be parsed (possibly a scanned image without OCR).",
                                   [entry("info", "Insufficient evidence",
                                          "No extractable text found in the offer letter.")],
                                   ["Upload a text-based PDF or provide the job URL/text."])
        elif ext in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
            img = image_scanner(file_path, file_name)
            ocr_txt = img["meta"].get("ocr_text", "") if isinstance(img["meta"], dict) else ""
            if ocr_txt:
                content_parts.append(ocr_txt)
                substantive_parts.append(ocr_txt)
            for r in img["reasons"]:
                if r["severity"] in ("danger", "warning"):
                    reasons.append(r)
            if img["score"] is not None:
                score = min(score, img["score"])
    url_flags, url_host = [], ""
    if url:
        parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
        url_host = (parsed.hostname or "").lower().removeprefix("www.")
        is_flag, flag_reason = inspect_url(url)
        if is_flag:
            url_flags.append(flag_reason)
        if _is_suspicious_job_domain(url_host):
            url_flags.append("domain is on the flagged fake-internship list")
        domain_refs = _find_suspicious_job_refs(url_host)
        if domain_refs:
            url_flags.append("domain references flagged provider(s): %s"
                             % ", ".join(domain_refs))
        if url_flags:
            score -= 30
            reasons.append(entry("danger", "Suspicious job/internship URL",
                                 "; ".join(url_flags), "−30 points"))
        else:
            reasons.append(entry("success", "URL looks normal",
                                 "No suspicious URL patterns or flagged domains detected."))
        content_parts.append(url)
        if HAS_REQUESTS and current_app.config.get("LIVE_NETWORK", True):
            resp = _safe_request(url)
            if resp and HAS_BS4:
                soup = BeautifulSoup(resp.text[:200000], "html.parser")
                body = soup.get_text(" ", strip=True)[:3000]
                if len(body) > 60:
                    content_parts.append(body)
                    substantive_parts.append(body)
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()
                    content_parts.append(title)
                    substantive_parts.append(title)
    if text:
        content_parts.append(text)
        substantive_parts.append(text)

    combined = "\n".join(content_parts).strip()
    if not combined:
        return make_result(None, "insufficient", "unknown",
                           "No job content was provided.",
                           [entry("info", "Insufficient evidence", "Paste a posting, URL or upload the offer letter.")],
                           ["Provide the job/internship posting you want to verify."])
    lower = combined.lower()

    # Evidence gating: a bare URL with no readable page content cannot be verified.
    url_only_sparse = bool(url) and not text and not file_path \
        and len("\n".join(substantive_parts).strip()) < 60
    if url_only_sparse and not url_flags:
        return make_result(None, "insufficient", "unknown",
                           "Insufficient evidence - the posting could not be verified.",
                           reasons + [entry("info", "Insufficient evidence",
                                            "Only a URL was provided and no page content could be "
                                            "retrieved to analyse, so no score is assigned.")],
                           ["Provide the posting text or upload the offer letter, or enable "
                            "network access so the page can be fetched."])

    # Flagged internship provider named in the content --------------------------------
    ref_hits = _find_suspicious_job_refs(lower) if not url_flags else []
    if ref_hits:
        score -= 25
        reasons.append(entry("danger", "Flagged internship provider mentioned",
                             "The content references provider(s) repeatedly tied to bogus "
                             "internships: %s." % ", ".join(ref_hits[:6]), "−25 points"))

    # Platform domain match ---------------------------------------------------------
    platform = ""
    if url:
        try:
            host = urllib.parse.urlparse(url).hostname or ""
            host = host.lower().removeprefix("www.")
            platform = next((p for p in JOB_PLATFORM_DOMAINS if host.endswith(p)), "")
        except Exception:
            pass
    if platform:
        reasons.append(entry("success", "Recognised job platform",
                             "Posting is hosted on %s." % platform))
    elif url:
        reasons.append(entry("info", "Unknown hosting domain",
                             "The posting URL is not on a major job platform."))

    # Recruiter email domain ----------------------------------------------------------
    corporate_free_mail = False
    emails = re.findall(r"[\w.+-]+@([\w.-]+)", lower)
    company_claim = bool(COMPANY_CLAIM_RE.search(lower))
    if emails:
        suspicious = sorted({e.lower() for e in emails
                             if e.lower() in FREE_MAIL_DOMAINS
                             or any(f in e.lower() for f in ("gmail", "yahoo", "hotmail"))})
        if suspicious:
            if company_claim:
                score -= 30
                corporate_free_mail = True
                reasons.append(entry("danger", "Company claim with free-mail contact",
                                     "Posting claims to represent a company/organisation but the "
                                     "only contact is on %s - established companies use their own "
                                     "domains." % ", ".join(suspicious), "−30 points"))
            else:
                score -= 20
                reasons.append(entry("danger", "Free-mail recruiter contact",
                                     "Recruiter uses %s instead of an official company domain."
                                     % ", ".join(suspicious), "−20 points"))
        else:
            reasons.append(entry("success", "Recruiter email looks official",
                                 "Domain(s): %s." % ", ".join(sorted(set(emails)))))

    # Payment requests -------------------------------------------------------------------
    fees = [p for p in JOB_FEE_PHRASES if p in lower]
    if fees:
        score -= 35
        reasons.append(entry("danger", "Payment request found",
                             "The posting asks for: %s. Legitimate employers never charge candidates." % ", ".join(fees),
                             "−35 points"))
    else:
        reasons.append(entry("success", "No payment requested",
                             "No registration/processing fee language found."))

    # Mandatory paid training / certificate-mill language ----------------------------------
    paid_train = [p for p in PAID_TRAINING_PHRASES if p in lower]
    if paid_train:
        score -= 30
        reasons.append(entry("danger", "Mandatory paid training",
                             "The offer requires paid training/onboarding: %s. Genuine "
                             "employers pay you; they never charge you."
                             % ", ".join(paid_train), "−30 points"))
    cert_mill = [c for c in CERTIFICATE_MILL_PHRASES if c in lower]
    if cert_mill:
        score -= 15
        reasons.append(entry("warning", "Certificate-mill wording",
                             "The offer focuses on certificates rather than work: %s."
                             % ", ".join(cert_mill), "−15 points"))

    # Off-platform chat redirection (hard override trigger) -------------------------------
    chat_redirects = [k for k in JOB_CHAT_REDIRECT_KEYWORDS if k in lower]
    if chat_redirects:
        score -= 25
        reasons.append(entry("danger", "Redirection to personal chat channel",
                             "Posting asks you to move to %s. Recruiters contact candidates "
                             "through the official hiring process, not personal chat apps."
                             % ", ".join(chat_redirects), "−25 points"))
    else:
        reasons.append(entry("success", "No chat-app redirection",
                             "No WhatsApp/Telegram redirection language found."))

    # "Easy money" workflow tactics (deduction) ---------------------------------------------
    workflow_hits = [k for k in JOB_SCAM_WORKFLOW_KEYWORDS if k in lower]
    if workflow_hits:
        penalty = min(20 * len(workflow_hits), 40)
        score -= penalty
        reasons.append(entry("danger", "Scam 'easy money' workflow pattern",
                             "Phrases typical of fake jobs: %s."
                             % ", ".join(workflow_hits), "−%d points" % penalty))

    # Unrealistic salary ---------------------------------------------------------------------
    salary_flags = [label for pat, label in UNREALISTIC_SALARY if re.search(pat, lower)]
    if salary_flags:
        score -= 15
        reasons.append(entry("warning", "Unrealistic compensation",
                             "Flags: %s." % "; ".join(salary_flags), "−15 points"))

    # Grammar -----------------------------------------------------------------------------------
    issues = [label for pat, label in GRAMMAR_ISSUES if re.search(pat, lower)]
    if len(issues) >= 2:
        score -= 10
        reasons.append(entry("warning", "Poor grammar / scam wording",
                             "Multiple grammatical issues detected.", "−10 points"))

    # Missing company details ----------------------------------------------------------------------
    has_reg = bool(re.search(r"\b(CIN|GSTIN|GST|LLP|INC|LTD|PVT|LIMITED|CORPORATION)\b", lower, re.I))
    if has_reg:
        reasons.append(entry("success", "Company identifiers present",
                             "The posting includes registration/legal identifiers."))
    else:
        score -= 5
        reasons.append(entry("warning", "Missing company details",
                             "No registration number or legal entity markers found.", "−5 points"))

    # Urgency / scam wording -------------------------------------------------------------------------
    urgent = [k for k in HIGH_PRESSURE_KEYWORDS if re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", lower)]
    if urgent:
        score -= 15
        reasons.append(entry("danger", "High-pressure language",
                             "Urgency phrases: %s." % ", ".join(urgent[:6]), "−15 points"))

    score = max(0, min(100, score))

    # Scam override ---------------------------------------------------------------------------
    # A hard trigger (upfront fee, chat-app redirection, or a company claim made only via a
    # free personal email) forces a High Risk / Scam verdict (score 0-20) regardless of how
    # clean the rest of the posting looks. A suspicious/fake internship URL, mandatory paid
    # training, or a flagged provider name caps the score at 30 (High Risk) instead.
    scam_hits, hard_cap = [], 100
    if fees:
        scam_hits.append("an upfront payment requirement (%s)" % ", ".join(fees))
        hard_cap = min(hard_cap, 20)
    if chat_redirects:
        scam_hits.append("redirection to a personal chat channel (%s)"
                         % ", ".join(chat_redirects))
        hard_cap = min(hard_cap, 20)
    if corporate_free_mail:
        scam_hits.append("a free personal email while claiming to represent a company")
        hard_cap = min(hard_cap, 20)
    if scam_hits:
        score = min(score, hard_cap)
        summary = ("High Risk / Potential Job Scam - %s. Legitimate employers never charge "
                   "applicants or recruit through personal chat channels."
                   % "; ".join(scam_hits))
    else:
        override_hits = []
        if url_flags:
            override_hits.append("a suspicious/bogus internship URL (%s)"
                                 % "; ".join(url_flags))
        if paid_train:
            override_hits.append("mandatory paid training (%s)" % ", ".join(paid_train))
        if ref_hits:
            override_hits.append("references a flagged internship provider (%s)"
                                 % ", ".join(ref_hits[:6]))
        if override_hits:
            score = min(score, 30)
            summary = ("High Risk / Potential Fake Internship Offer - %s. "
                       "A legitimate internship never requires payment or a bogus "
                       "intermediary domain." % "; ".join(override_hits))
        else:
            summary = ("Job/internship analysis: domain, recruiter email, payment requests, "
                       "training fees, salary and wording checked.")

    return make_result(score, "verified", risk_for(score), summary, reasons,
                       ["If a fee is required to 'process' an offer, it is almost certainly a scam.",
                        "Contact the company via its official website, never via the posting's contact."],
                       {"type": "Job / Internship", "url": url or None, "url_host": url_host or None,
                        "url_flags": url_flags or None})


# --------------------------------------------------------------------------- #
#  News scanner - evidence-based fact checking
#
#  Pipeline: gather text (OCR / PDF / URL / paste) -> extract claim + entities
#  -> auto-generate search queries -> live trusted-source search -> fetch and
#  compare evidence -> evidence-based verdict + dynamic confidence.
#  Verdicts are NEVER decided by AI: the LLM, when configured, only writes an
#  explanation of the already-computed verdict.
# --------------------------------------------------------------------------- #

# --- Gazetteers & constants -------------------------------------------------

_NEWS_CACHE = {"page": {}, "search": {}}

_NEWS_DATE_PATTERNS = [
    r"\b\d{4}-\d{1,2}-\d{1,2}\b",
    r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
    r"\b\d{1,2}(?:st|nd|rd|th)?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{4}\b",
    r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*\d{4})?\b",
]
_NEWS_MONTHS = {"january", "february", "march", "april", "may", "june", "july",
                "august", "september", "october", "november", "december"}
_NEWS_RELATIVE_DATES = ["today", "yesterday", "last night", "this morning",
                        "this evening", "tonight", "last week", "last month",
                        "this week", "this month", "last year", "this year",
                        "days ago", "hours ago", "weeks ago", "months ago",
                        "a week ago", "a month ago"]

_NEWS_LOCATIONS = {
    "mumbai", "delhi", "new delhi", "bangalore", "bengaluru", "hyderabad",
    "chennai", "kolkata", "pune", "ahmedabad", "jaipur", "lucknow", "kanpur",
    "nagpur", "indore", "bhopal", "patna", "vadodara", "surat", "visakhapatnam",
    "vijayawada", "coimbatore", "madurai", "kochi", "kozhikode", "guwahati",
    "dehradun", "jammu", "srinagar", "chandigarh", "amritsar", "ludhiana",
    "kashmir", "kashmir valley", "jammu and kashmir",
    "raipur", "ranchi", "bhubaneswar", "siliguri", "agra", "varanasi", "noida",
    "gurugram", "gurgaon", "faridabad", "ghaziabad", "nashik", "aurangabad",
    "mangalore", "mangaluru", "mysuru", "mysore", "tirupati", "nellore",
    "tiruchirappalli", "salem", "thane", "gwalior", "jodhpur", "udaipur",
    "kota", "bikaner", "jalandhar", "panipat", "ambala", "shimla", "puri",
    "goa", "panaji", "itanagar", "dispur", "aizawl", "imphal", "agartala",
    "shillong", "gangtok", "kohima", "leh", "port blair", "silvassa",
    "andhra pradesh", "arunachal pradesh", "assam", "bihar", "chhattisgarh",
    "gujarat", "haryana", "himachal pradesh", "jharkhand", "karnataka",
    "kerala", "madhya pradesh", "maharashtra", "manipur", "meghalaya",
    "mizoram", "nagaland", "odisha", "punjab", "rajasthan", "sikkim",
    "tamil nadu", "telangana", "tripura", "uttar pradesh", "uttarakhand",
    "west bengal", "jammu and kashmir", "andaman and nicobar", "lakshadweep",
    "puducherry", "london", "paris", "berlin", "madrid", "rome", "moscow",
    "kyiv", "kiev", "beijing", "shanghai", "hong kong", "tokyo", "seoul",
    "singapore", "bangkok", "dubai", "abu dhabi", "doha", "riyadh",
    "tel aviv", "jerusalem", "gaza", "tehran", "istanbul", "ankara", "cairo",
    "lagos", "nairobi", "addis ababa", "johannesburg", "cape town", "sydney",
    "melbourne", "toronto", "vancouver", "new york", "new york city",
    "washington", "washington dc", "los angeles", "chicago", "houston",
    "san francisco", "miami", "boston", "seattle", "denver", "atlanta",
    "ottawa", "mexico city", "sao paulo", "buenos aires", "santiago", "lima",
    "bogota", "karachi", "islamabad", "lahore", "dhaka", "colombo",
    "kathmandu", "yangon", "hanoi", "ho chi minh city", "jakarta", "manila",
    "kuala lumpur", "brussels", "amsterdam", "stockholm", "oslo", "helsinki",
    "copenhagen", "warsaw", "vienna", "zurich", "geneva", "prague", "budapest",
    "athens", "lisbon", "dublin", "edinburgh", "abuja", "accra", "dakar",
    "casablanca", "algiers", "baghdad", "damascus", "amman", "beirut",
    "kabul", "tashkent", "astana", "baku", "yerevan", "tbilisi", "minsk",
    "sofia", "bucharest", "belgrade", "zagreb", "tirana", "india", "china",
    "united states", "usa", "united states of america", "uk", "united kingdom",
    "russia", "ukraine", "france", "germany", "italy", "spain", "portugal",
    "poland", "sweden", "norway", "finland", "denmark", "netherlands",
    "belgium", "austria", "switzerland", "greece", "turkey", "israel",
    "palestine", "lebanon", "syria", "iraq", "iran", "afghanistan",
    "pakistan", "bangladesh", "nepal", "bhutan", "sri lanka", "maldives",
    "myanmar", "thailand", "vietnam", "laos", "cambodia", "malaysia",
    "indonesia", "philippines", "japan", "south korea", "north korea",
    "mongolia", "kazakhstan", "uzbekistan", "azerbaijan", "armenia",
    "georgia", "brazil", "argentina", "chile", "colombia", "peru",
    "venezuela", "egypt", "libya", "tunisia", "algeria", "morocco", "mali",
    "niger", "chad", "sudan", "south sudan", "ethiopia", "eritrea", "somalia",
    "kenya", "uganda", "tanzania", "rwanda", "burundi", "congo", "nigeria",
    "ghana", "senegal", "cameroon", "zimbabwe", "zambia", "mozambique",
    "angola", "namibia", "botswana", "madagascar", "mauritius", "australia",
    "new zealand", "fiji", "canada", "saudi arabia", "uae", "qatar",
    "kuwait", "oman", "bahrain", "yemen", "jordan", "taiwan",
}

_NEWS_ORGS = {
    "united nations", "world health organization", "who", "nato",
    "european union", "imf", "world bank", "wto", "unesco", "unicef",
    "security council", "supreme court", "high court", "lok sabha",
    "rajya sabha", "parliament", "election commission", "election commission of india",
    "reserve bank of india", "rbi", "sebi", "isro", "drdo", "cbse", "niti aayog",
    "nabard", "central bureau of investigation", "cbi", "enforcement directorate",
    "national investigation agency", "nia", "isro", "bcci", "iit", "iim",
    "indian national congress", "congress", "bjp", "aap", "tmc", "dmk",
    "shiv sena", "ncp", "trinamool", "rss", "barc", "indian army", "indian navy",
    "indian air force", "ministry of defence", "ministry of health",
    "ministry of home affairs", "ministry of finance", "ministry of external affairs",
    "ministry of railways", "ministry of agriculture", "prime minister's office",
    "cabinet", "delhi police", "mumbai police", "bombay high court",
    "delhi high court", "airports authority of india", "state bank of india",
    "sbi", "ngt", "nasa", "spacex", "tesla", "google", "meta", "microsoft",
    "apple", "amazon", "netflix", "openai", "youtube", "whatsapp", "telegram",
    "instagram", "linkedin", "x corp", "world trade organization", "european union",
}

_NEWS_ORG_SUFFIXES = [
    "university", "college", "institute", "hospital", "ministry", "department",
    "commission", "committee", "board", "bureau", "authority", "corporation",
    "corpn", "council", "association", "foundation", "organization",
    "organisation", "agency", "bank", "airport", "court", "police", "force",
    "army", "navy", "air force", "group", "party", "movement", "team",
    "company", "ltd", "inc", "news agency", "government", "assembly",
    "parliament", "congress", "federation",
]

_NEWS_TITLE_WORDS = {
    "the", "a", "an", "and", "but", "for", "nor", "yet", "so", "on", "at",
    "in", "from", "with", "by", "to", "of", "as", "into", "upon", "via",
    "when", "what", "who", "whom", "why", "how", "this", "that", "these",
    "those", "there", "their", "they", "you", "your", "our", "i", "he", "she",
    "it", "we", "mr", "mrs", "ms", "dr", "prof", "govt", "government",
    "prime", "chief", "home", "finance", "defence", "foreign", "railway",
    "education", "health", "law", "new", "south", "north", "east", "west",
    "india", "indian", "is", "are", "was", "were", "be", "been", "has",
    "have", "had", "will", "would", "should", "could", "may", "might", "must",
    "can", "not", "no", "yes", "all", "each", "every", "many", "some", "most",
    "more", "than", "then", "since", "while", "during", "before", "after",
    "also", "only", "just", "even", "still", "yet", "back", "over", "under",
    "about", "between", "among", "against", "around", "next", "last", "first",
    "second", "third", "one", "two", "three", "four", "five", "six", "seven",
    "eight", "nine", "ten", "hundred", "thousand", "million", "billion",
    "today", "yesterday", "tomorrow", "today's", "yesterday's", "amid", "after",
    "says", "say", "said", "saying", "report", "reports", "reported",
}

_NEWS_KEYWORD_STOP = _NEWS_TITLE_WORDS | {
    "would", "could", "should", "might", "really", "very", "much", "many",
    "make", "made", "making", "said", "says", "say", "told", "tells", "get",
    "gets", "got", "will", "shall", "into", "across", "along", "among",
}

# Capitalised common nouns / job titles that are not person names; single-word
# matches in this set are never treated as named people.
_NEWS_COMMON_NOUNS = {
    "police", "pellet", "guns", "gun", "crowd", "control", "protest",
    "protesters", "minister", "officials", "government", "security", "forces",
    "committee", "board", "commission", "party", "court", "assembly",
    "parliament", "statement", "report", "reports", "centre", "center",
    "state", "district", "village", "city", "army", "navy", "airstrike",
    "strike", "crisis", "summit", "meeting", "election", "budget", "policy",
    "bill", "law", "school", "hospital", "airport", "station", "market",
    "price", "bank", "company", "firm", "industry", "sector", "index",
    "sports", "team", "league", "match", "series", "tournament", "winter",
    "summer", "monsoon", "east", "west", "north", "south", "opposition",
    "leader", "president", "chief", "top", "senior", "former", "first",
    "second", "world", "country", "india", "prime", "defence", "finance",
    "home", "foreign", "railway", "education", "health", "power", "water",
    "road", "train", "bus", "plane", "flight", "ship", "stock", "share",
    "number", "week", "month", "year", "state", "centre", "today", "yesterday",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
    "sunday", "january", "february", "march", "april", "june", "july",
    "august", "september", "october", "november", "december", "morning",
    "afternoon", "evening", "night", "noon",
}


# --- Cache helpers -----------------------------------------------------------

def _news_cache_get(kind, key):
    entry = _NEWS_CACHE.get(kind, {}).get(key)
    if entry and entry[0] > time.time():
        return entry[1]
    return None


def _news_cache_put(kind, key, value):
    ttl = current_app.config.get("NEWS_CACHE_TTL", 3600) if current_app else 3600
    _NEWS_CACHE.setdefault(kind, {})[key] = (time.time() + ttl, value)


# --- Text cleaning -----------------------------------------------------------

def _clean_ocr_text(raw):
    """Normalise OCR / PDF text: whitespace, smart quotes, hyphen line breaks."""
    if not raw:
        return ""
    t = str(raw)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    t = t.replace("\u2019", "'").replace("\u2018", "'")
    t = t.replace("\u201c", '"').replace("\u201d", '"')
    t = re.sub(r"(?<=\w)-\n(?=\w)", "", t)
    t = re.sub(r"\s+\n", "\n", t)
    return t.strip()


def _parse_iso_date(value):
    """Parse an ISO-8601 or RFC-2822 date into 'DD Mon YYYY' ('' when unusable)."""
    if not value:
        return ""
    try:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        return dt.strftime("%d %b %Y")
    except Exception:
        try:
            dt = parsedate_to_datetime(str(value))
            return dt.strftime("%d %b %Y")
        except Exception:
            return ""


def _article_meta_date(soup):
    """Extract a publication date from page metadata or <time> elements."""
    if soup is None:
        return ""
    for attr in ("article:published_time", "datePublished", "pubdate",
                 "sailthru.date", "dc.date", "og:published_time"):
        tag = soup.find("meta", {"property": attr}) or soup.find("meta", {"name": attr})
        if tag and tag.get("content"):
            parsed = _parse_iso_date(tag["content"])
            if parsed:
                return parsed
    time_tag = soup.find("time", {"datetime": True}) or soup.find("time")
    if time_tag is not None:
        dt = time_tag.get("datetime") or time_tag.get_text()
        if dt:
            parsed = _parse_iso_date(dt)
            if parsed:
                return parsed
    return ""


def _article_page(link):
    """Fetch + strip a news article, cached. Returns a dict or None."""
    if not link or not (HAS_REQUESTS and HAS_BS4):
        return None
    if not current_app.config.get("LIVE_NETWORK", True):
        return None
    cached = _news_cache_get("page", link)
    if cached is not None:
        return cached
    try:
        r = requests.get(link, timeout=10,
                         headers={"User-Agent": "Mozilla/5.0 (TrustLens/1.0)"})
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text[:400000], "html.parser")
        for tag in soup(["script", "style", "nav", "header", "footer",
                         "aside", "form", "noscript"]):
            tag.decompose()
        text = _clean_ocr_text(soup.get_text(" ", strip=True))[:3000]
        title = (soup.title.get_text(strip=True) if soup.title else "")[:200]
        published = _article_meta_date(soup)
        domain = (urllib.parse.urlparse(link).hostname or "").lower()
        domain = domain.removeprefix("www.")
        out = {"text": text, "title": title, "published": published,
               "domain": domain, "link": link}
        _news_cache_put("page", link, out)
        return out
    except Exception:
        return None


def _fetch_article_text(link):
    """Fetch and strip a news article to readable body text (<=3000 chars)."""
    page = _article_page(link)
    return (page or {}).get("text", "") or ""


def _extract_main_claim(headline, content):
    """Derive a compact claim statement from the headline + first sentences."""
    hd = (headline or "").strip()
    combined = (content or "").strip()
    sentences = re.split(r"(?<=[.!?])\s+", combined)
    first = ""
    for s in sentences:
        s = s.strip().strip("\"'")
        if len(s) >= 15:
            first = s
            break
    if hd:
        claim = hd
    elif first:
        claim = first
    else:
        claim = combined[:220]
    return {"headline": hd or (first or combined[:120]),
            "claim": claim[:300], "first_sentence": first}


def _detect_headline_quality(headline, content):
    """Return (clickbait, misleading, missing_context) lists of signals."""
    hd = (headline or "").strip()
    lower_hd = hd.lower()
    lower = (content or "").lower()
    clickbait, misleading, missing = [], [], []
    for pat in CLICKBAIT_PATTERNS:
        if re.search(pat, lower_hd):
            clickbait.append(pat.replace("\\b", "").replace("\\d+", "N"))
    letters = re.sub(r"[^a-zA-Z]", "", hd)
    if letters and sum(1 for c in letters if c.isupper()) / len(letters) > 0.6:
        misleading.append("ALL CAPS headline - sensational tabloid style")
    if re.search(r"[!?]{2,}|!\?|\?!", hd):
        misleading.append("heavy punctuation (!?!!) typical of engagement bait")
    if re.search(r"\b(?:biggest|worst|best|greatest|first ever|never before|"
                 r"unprecedented)\b", lower_hd):
        misleading.append("unverifiable superlative claim")
    if re.search(r"\b(?:experts say|people are saying|sources say|some reports "
                 r"claim)\b", lower_hd):
        misleading.append("unnamed 'experts/sources' cited without evidence")
    if hd.rstrip().endswith("?") and not re.search(
            r"\b(?:said|confirmed|denied|because|according to)\b", lower[:600]):
        misleading.append("question headline the article does not clearly answer")
    if not hd:
        missing.append("no headline provided")
    elif len(hd.split()) < 5:
        missing.append("headline is too short to convey context")
    if len((content or "").strip()) < 80:
        missing.append("article body is missing or too short for full context")
    return clickbait, misleading, missing


# --- Entity + date extraction ------------------------------------------------

def _extract_news_entities(headline, content):
    """Best-effort extraction of persons, locations, orgs and dates."""
    text = " ".join([(headline or ""), (content or "")])
    lower = text.lower()
    entities = {"persons": [], "locations": [], "orgs": [],
                "dates": [], "relative_dates": []}

    # Dates -----------------------------------------------------------------
    found_dates = set()
    for pat in _NEWS_DATE_PATTERNS:
        for m in re.finditer(pat, text):
            found_dates.add(re.sub(r"\s+", " ", m.group(0)).strip())
    for rd in _NEWS_RELATIVE_DATES:
        if re.search(r"\b%s\b" % rd, lower):
            found_dates.add(rd)
    entities["dates"] = [d for d in found_dates if len(d) <= 40][:8]
    entities["relative_dates"] = [d for d in found_dates
                                  if " " not in d and d.lower() in _NEWS_RELATIVE_DATES][:4]

    # Locations ---------------------------------------------------------------
    found_locs = []
    for loc in sorted(_NEWS_LOCATIONS, key=len, reverse=True):
        if re.search(r"(?<![a-z])%s(?![a-z])" % re.escape(loc.lower()), lower):
            found_locs.append(loc.title())
    entities["locations"] = found_locs[:8]

    # Orgs --------------------------------------------------------------------
    found_orgs = []
    for org in sorted(_NEWS_ORGS, key=len, reverse=True):
        if re.search(r"(?<![a-z])%s(?![a-z])" % re.escape(org.lower()), lower):
            found_orgs.append(org.title())
    suffix_re = r"\b[A-Z][A-Za-z&'-]*(?:\s+[A-Z][A-Za-z&'-]*){0,3}\s+(%s)\b" % "|".join(
        _NEWS_ORG_SUFFIXES)
    for m in re.finditer(suffix_re, text):
        phrase = re.sub(r"\s+", " ", m.group(0)).strip()
        if phrase.lower() not in {o.lower() for o in found_orgs}:
            found_orgs.append(phrase)
    entities["orgs"] = found_orgs[:8]

    # Persons -----------------------------------------------------------------
    found_persons = []
    stop_lower = _NEWS_TITLE_WORDS | _NEWS_LOCATIONS | {o.lower() for o in _NEWS_ORGS}
    for m in re.finditer(r"\b[A-Z][a-zA-Z'-]+(?:\s+[A-Z][a-zA-Z'-]+){0,2}\b", text):
        phrase = re.sub(r"\s+", " ", m.group(0)).strip()
        words = phrase.split()
        if len(words) > 3:
            continue
        if phrase.isupper() or any(ch.isdigit() for ch in phrase):
            continue
        if any(w in stop_lower for w in phrase.lower().split()):
            continue
        if phrase.rstrip("'").endswith("'"):
            continue
        if any(phrase.lower().endswith(s) for s in ("university", "ministry",
                                                    "commission", "authority")):
            continue
        if any(w.lower() in _NEWS_LOCATIONS for w in words) and len(words) <= 2:
            continue
        before = text[max(0, m.start() - 2):m.start()]
        at_sentence_start = (not before.strip() or re.search(r"[.!?]\s*$", before))
        if len(words) == 1 and (at_sentence_start or phrase.lower() in _NEWS_COMMON_NOUNS):
            continue
        if phrase.lower() in {p.lower() for p in found_persons}:
            continue
        found_persons.append(phrase)
    entities["persons"] = found_persons[:8]
    return entities


def _evidence_entity_overlap(entities, text):
    """Fraction of claim persons/locations/orgs present in the evidence text."""
    keys = ((entities or {}).get("persons", []) +
            (entities or {}).get("locations", []) +
            (entities or {}).get("orgs", []))
    if not keys:
        return 0.0
    lower = text.lower()
    hits = sum(1 for k in keys if k.lower() in lower)
    return round(hits / len(keys), 2)


def _date_fingerprints(text):
    out = set()
    for m in re.finditer(r"\b\d{1,2}(?:st|nd|rd|th)?\s+"
                         r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*"
                         r"(\s+\d{4})?", text.lower()):
        mon = m.group(1)
        out.add(mon)
        if m.group(2):
            out.add(mon + m.group(2).strip())
    for m in re.finditer(r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*"
                         r"\s+\d{1,2}(?:st|nd|rd|th)?(?:\s*,\s*\d{4})?", text.lower()):
        mon = m.group(1)
        out.add(mon)
        yr = re.search(r"\d{4}", m.group(0))
        if yr:
            out.add(mon + yr.group(0))
    return out


def _evidence_date_consistent(claim_dates, text):
    """True/False/None - does the evidence mention the claim's time window?"""
    if not claim_dates:
        return None
    cf = _date_fingerprints(" ".join(claim_dates))
    if not cf:
        return None
    ef = _date_fingerprints(text)
    return bool(cf & ef)


# --- Search-query generation -------------------------------------------------

def _significant_keywords(claim, content, limit=3):
    tokens = Counter(w for w in re.findall(r"[A-Za-z][A-Za-z'-]{4,}",
                                           (content or ""))
                     if w.lower() not in _NEWS_KEYWORD_STOP)
    return [w for w, _ in tokens.most_common(limit)]


def _build_search_queries(claim, headline, entities, content):
    """Auto-generate up to 4 targeted search queries from the claim + entities."""
    queries, seen = [], set()

    def add(q):
        q = re.sub(r"\s+", " ", (q or "")).strip().strip("?!.,;:")
        q = re.sub(r"\s+", " ", q)
        key = q.lower()
        if len(q) >= 8 and key not in seen:
            seen.add(key)
            queries.append(q[:160])

    ent = entities or {}
    persons = ent.get("persons") or []
    locations = ent.get("locations") or []
    orgs = ent.get("orgs") or []
    dates = ent.get("dates") or []

    add(claim)
    add(headline)
    base = " ".join((persons[:1] + locations[:1] + orgs[:1]))
    kws = _significant_keywords(claim, content)
    add(" ".join((base + " " + " ".join(kws)).split()))
    if dates:
        add(" ".join((base + " " + dates[0]).split()))
    if not queries and claim:
        add(claim[:120])
    return queries[:4]


# --- Live trusted-source search ---------------------------------------------

def _hostname_label(url):
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    return host.removeprefix("www.") or "search result"


def _decode_duckduckgo_url(href):
    if "duckduckgo.com/l/" in href and "uddg=" in href:
        parsed = urllib.parse.urlparse(href)
        q = urllib.parse.parse_qs(parsed.query)
        if q.get("uddg"):
            return urllib.parse.unquote(q["uddg"][0])
    return href


def _filter_trusted_domains(results, limit=8):
    """Keep only hits whose hostname matches the trusted-domain allowlist."""
    domains = current_app.config.get("TRUSTED_NEWS_DOMAINS", []) if current_app else []
    if not domains:
        domains = list(_NEWS_ORG_SUFFIXES)  # unlikely path; keep safe
    seen, out = set(), []

    def trusted(url):
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in domains)

    for r in results:
        url = (r.get("url") or "").strip()
        if not url or not url.startswith("http"):
            continue
        if not trusted(url):
            continue
        host = urllib.parse.urlparse(url).hostname or ""
        key = host + "|" + urllib.parse.urlparse(url).path[:80]
        if key in seen:
            continue
        seen.add(key)
        out.append({"title": (r.get("title") or "").strip(),
                    "url": url,
                    "snippet": (r.get("snippet") or "").strip(),
                    "source": _hostname_label(url)})
        if len(out) >= limit:
            break
    return out


def _search_duckduckgo(query, limit=8):
    results = []
    r = requests.post("https://html.duckduckgo.com/html/",
                      data={"q": query},
                      headers={"User-Agent": "Mozilla/5.0 (TrustLens/1.0)"},
                      timeout=10)
    if r.status_code != 200:
        return results
    soup = BeautifulSoup(r.text, "html.parser")
    for res in soup.select("a.result__a")[: limit * 3]:
        title = res.get_text(strip=True)
        href = _decode_duckduckgo_url(res.get("href") or "")
        snippet = ""
        parent = res.find_parent("div", class_="result")
        if parent:
            sn = parent.select_one(".result__snippet")
            if sn:
                snippet = sn.get_text(strip=True)
        if title and href.startswith("http"):
            results.append({"title": title, "url": href, "snippet": snippet})
    return results


def _search_bing(query, limit=8):
    results = []
    r = requests.get("https://www.bing.com/search",
                     params={"q": query, "count": str(limit)},
                     headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; "
                                            "Win64; x64) AppleWebKit/537.36"},
                     timeout=10)
    if r.status_code != 200:
        return results
    soup = BeautifulSoup(r.text, "html.parser")
    for li in soup.select("li.b_algo")[: limit * 3]:
        a = li.select_one("h2 a")
        if not a:
            continue
        href = a.get("href") or ""
        title = a.get_text(strip=True)
        snippet = ""
        cap = li.select_one(".b_caption p") or li.select_one(".b_snippet")
        if cap:
            snippet = cap.get_text(strip=True)
        if title and href.startswith("http"):
            results.append({"title": title, "url": href, "snippet": snippet})
    return results


def _search_serpapi(query, api_key, limit=8):
    results = []
    r = requests.get("https://serpapi.com/search.json",
                     params={"engine": "google", "q": query,
                             "api_key": api_key, "num": limit},
                     timeout=10)
    if r.status_code != 200:
        return results
    data = r.json()
    for o in (data.get("organic_results") or [])[: limit * 3]:
        results.append({"title": o.get("title") or "",
                        "url": o.get("link") or "",
                        "snippet": o.get("snippet") or o.get("content") or ""})
    return results


def _search_news_web(query, limit=8):
    """Live search restricted to trusted outlets. Returns [] when offline."""
    if not (current_app.config.get("LIVE_NETWORK", True) and HAS_REQUESTS and HAS_BS4):
        return []
    api_key = (current_app.config.get("NEWS_SEARCH_API_KEY", "") if current_app else "")
    engine = (current_app.config.get("NEWS_SEARCH_API_ENGINE", "serpapi")
              if current_app else "serpapi")
    ckey = ("api:%s" % engine if api_key else "keyless") + "|" + query
    cached = _news_cache_get("search", ckey)
    if cached is not None:
        return cached
    raw = []
    if api_key:
        try:
            raw = _search_serpapi(query, api_key, limit)
        except Exception:
            raw = []
    if not raw:
        try:
            raw = _search_duckduckgo(query, limit)
        except Exception:
            raw = []
    if not raw:
        try:
            raw = _search_bing(query, limit)
        except Exception:
            raw = []
    results = _filter_trusted_domains(raw, limit)
    _news_cache_put("search", ckey, results)
    return results


# --- Evidence comparison -----------------------------------------------------

def _compare_claim_evidence(claim, entities, title, body_text, published=""):
    """Classify one evidence article as support / contradict / related / none."""
    title = title or ""
    body_text = body_text or ""
    combined = (body_text + " " + title).strip()
    t_sim = claim_similarity(claim, [title])[0]
    b_sim = claim_similarity(claim, [body_text])[0] if body_text.strip() else 0.0
    sim = max(t_sim, b_sim)
    overlap = _evidence_entity_overlap(entities, combined)
    flip = _polarity_flip(claim, combined)
    date_ok = _evidence_date_consistent((entities or {}).get("dates", []),
                                        combined + " " + (published or ""))

    if flip and (b_sim >= 0.22 or t_sim >= 0.45):
        category = "contradict"
    elif body_text and (b_sim >= 0.30 or (b_sim >= 0.24 and overlap >= 0.4)):
        category = "support"
    elif t_sim >= 0.45:
        category = "support"
    elif t_sim >= 0.24 or (body_text and b_sim >= 0.18):
        category = "related"
    else:
        category = "none"

    if category == "support" and not body_text and t_sim < 0.55 and overlap < 0.3:
        category = "related"

    return {"category": category, "sim": round(sim, 3),
            "title_sim": round(t_sim, 3), "body_sim": round(b_sim, 3),
            "entity_overlap": overlap, "date_consistent": date_ok}


def _news_confidence(supporting, max_sim, entity_overlap, related,
                     clickbait, misleading_count):
    """Dynamic confidence (0-98) derived only from gathered evidence."""
    if supporting >= 5:
        base = 95
    elif supporting == 4:
        base = 92
    elif supporting == 3:
        base = 88
    elif supporting == 2:
        base = 82
    elif supporting == 1:
        base = 72
    elif related:
        base = 35
    else:
        base = 15
    adjust = int(round((max_sim - 0.5) * 20))
    adjust += int(round((entity_overlap - 0.5) * 20))
    if clickbait:
        adjust -= 8
    adjust -= 3 * misleading_count
    return max(5, min(98, base + adjust))


def _news_contradiction_confidence(contradicting, max_sim, entity_overlap,
                                   clickbait):
    """Confidence that the contradiction is real, from contradicting sources."""
    if contradicting >= 5:
        base = 95
    elif contradicting == 4:
        base = 92
    elif contradicting == 3:
        base = 88
    elif contradicting == 2:
        base = 82
    else:
        base = 62
    adjust = int(round((max_sim - 0.5) * 20))
    adjust += int(round((entity_overlap - 0.5) * 20))
    if clickbait:
        adjust -= 6
    return max(20, min(95, base + adjust))


# --- Explanation -------------------------------------------------------------

def _explain_verdict(verdict, supporting, contradicting, related,
                     sources, confidence, offline=False):
    names = ", ".join(s["source"] for s in sources[:3] if s.get("source")) or "trusted sources"
    if offline:
        return "Unable to verify because live internet search is unavailable."
    if verdict == "verified":
        return ("This claim matches reports published by %s. The locations, "
                "people and timeline are consistent across %d trusted sources, "
                "so the claim is Verified with %d%% confidence."
                % (names, supporting, confidence))
    if verdict == "partially_verified":
        return ("Part of this claim is confirmed by %s, but other details could "
                "not be confirmed across trusted sources, so it is Partially "
                "Verified with %d%% confidence." % (names, confidence))
    if verdict == "contradicted":
        return ("Reliable sources disagree with this claim - %s report the "
                "opposite, so it is Contradicted by Reliable Sources."
                % names)
    if related:
        return ("This claim could not be fully confirmed: %d related report(s) "
                "were found but none matched closely enough to support it."
                % related)
    return ("This claim could not be confirmed because no trusted news "
            "organization reported this event, so the verdict is Insufficient "
            "Evidence.")


def _llm_news_explanation(claim, verdict_label, supporting, contradicting,
                          source_names):
    """Optional AI explanation - written AFTER the evidence verdict is decided,
    so the AI can describe but never decide the outcome."""
    ai_key = os.environ.get("TRUSTLENS_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not (ai_key and HAS_REQUESTS and current_app.config.get("LIVE_NETWORK", True)):
        return ""
    summary = ("Supporting sources: %d (%s). Contradicting sources: %d."
               % (supporting, ", ".join(source_names[:3]) or "none",
                  contradicting))
    try:
        payload = {
            "model": CLAIM_LLM_MODEL,
            "messages": [
                {"role": "system",
                 "content": "You are an impartial fact-checking assistant. "
                            "The verdict (%s) was already computed from "
                            "evidence. Write a short 2-3 sentence explanation of "
                            "that verdict using ONLY the evidence summary below. "
                            "Do not invent facts." % verdict_label},
                {"role": "user",
                 "content": "Claim: %s\n\n%s" % (claim, summary)},
            ],
            "temperature": 0.2,
            "max_tokens": 160,
        }
        r = requests.post(CLAIM_LLM_URL, headers={
            "Authorization": "Bearer %s" % ai_key,
            "Content-Type": "application/json"}, json=payload, timeout=20)
        if r.status_code != 200:
            return ""
        data = r.json()
        return (data["choices"][0]["message"]["content"] or "").strip()
    except Exception:
        return ""


def _fetch_feed_titles():
    """Fetch trusted RSS feeds; return list of {title, link, source, published}.

    Uses the stdlib ElementTree parser (no lxml dependency) so it tolerates
    RSS namespaces. Empty on failure or when live network checks are disabled.
    """
    from xml.etree import ElementTree as ET
    items = []
    if not (current_app.config.get("LIVE_NETWORK", True) and HAS_REQUESTS):
        return items

    def local(tag):
        return tag.split("}", 1)[-1] if "}" in tag else tag

    def child_text(el, name):
        for ch in el:
            if local(ch.tag) == name and ch.text:
                return ch.text.strip()
        return ""

    for feed in current_app.config.get("TRUSTED_NEWS_FEEDS", []):
        if isinstance(feed, dict):
            name, url = feed.get("name", ""), feed.get("url", "")
        else:
            name, url = "", feed
        if not url:
            continue
        try:
            r = requests.get(url, timeout=8,
                             headers={"User-Agent": "Mozilla/5.0 (TrustLens/1.0)"})
            if r.status_code != 200:
                continue
            root = ET.fromstring(r.text[:800000])
            count = 0
            for el in root.iter():
                if local(el.tag) != "item":
                    continue
                title = child_text(el, "title")
                link = child_text(el, "link")
                published = _parse_iso_date(child_text(el, "pubDate"))
                if title:
                    items.append({"title": title, "link": link,
                                  "source": name or "", "published": published})
                count += 1
                if count >= 25:
                    break
        except Exception:
            continue
    return items


def news_scanner(url="", headline="", text="", file_path=None, file_name=""):
    """Evidence-based news fact-checking.

    Accepts a headline, article text, a news URL and/or a screenshot (OCR) or
    PDF. Extracts the main claim + entities, auto-generates search queries,
    runs a live trusted-source search (RSS feeds + keyless DuckDuckGo/Bing or
    an optional search API, filtered to a trusted-domain allowlist), fetches
    and compares each candidate article, then emits one of four evidence-backed
    verdicts - Verified / Partially Verified / Insufficient Evidence /
    Contradicted by Reliable Sources - with a confidence derived only from the
    evidence gathered. The LLM (when configured) writes the explanation of the
    verdict but never decides it.
    """
    reasons, suggestions = [], []
    score = None
    content_parts = []
    headline_hints = []
    publication_date = ""
    source_domain = ""

    # 1. Gather text: paste, PDF, screenshot OCR, or fetched URL -----------------
    if (text or "").strip():
        content_parts.append((text or "").strip())

    if file_path:
        ext = (file_name.rsplit(".", 1)[-1] if "." in file_name else "").lower()
        if ext == "pdf":
            pdf_text = extract_pdf_text(file_path)
            if pdf_text:
                pdf_text = _clean_ocr_text(pdf_text)
                content_parts.append(pdf_text)
                reasons.append(entry("success", "PDF parsed",
                                     "Extracted %d characters from the PDF."
                                     % len(pdf_text)))
            else:
                reasons.append(entry("info", "PDF uploaded",
                                     "No text could be extracted from the PDF "
                                     "(possibly a scanned document without OCR)."))
        else:
            img = image_scanner(file_path, file_name or "news_upload.png")
            img_meta = img["meta"] if isinstance(img["meta"], dict) else {}
            ocr_text = img_meta.get("ocr_text", "") or ""
            if ocr_text:
                ocr_text = _clean_ocr_text(ocr_text)
                content_parts.append(ocr_text)
                reasons.append(entry("success", "Text extracted from image",
                                     "OCR recovered %d characters from the screenshot."
                                     % len(ocr_text)))
                first_line = next((l.strip() for l in ocr_text.splitlines()
                                   if len(l.strip()) >= 8), "")
                if not headline and first_line:
                    headline_hints.append(first_line)
            else:
                reasons.append(entry("info", "Image uploaded",
                                     "No reliable text could be OCR'd from the image."))
            for r in img["reasons"]:
                if r["severity"] in ("danger", "warning"):
                    reasons.append(r)

    if url:
        resp = _safe_request(url)
        if resp is None:
            reasons.append(entry("warning", "Article unreachable",
                                 "The URL did not respond; content checks are limited."))
        elif HAS_BS4:
            soup = BeautifulSoup(resp.text[:300000], "html.parser")
            title = (soup.title.string.strip() if soup.title and soup.title.string else "")
            if not headline and title:
                headline_hints.append(title)
            body = _clean_ocr_text(soup.get_text(" ", strip=True))
            content_parts.append(body[:4000])
            source_domain = (urllib.parse.urlparse(resp.url).hostname or "").lower()
            source_domain = source_domain.removeprefix("www.")
            if not publication_date:
                publication_date = _article_meta_date(soup)
            reasons.append(entry("success", "Article content fetched",
                                 "Retrieved the page for analysis."))

    extracted_headline = (headline or (headline_hints[0] if headline_hints else "")).strip()
    content = "\n\n".join(p.strip() for p in content_parts if p and p.strip())
    combined = (content + " " + extracted_headline).strip()
    if len(combined) < 25:
        return make_result(
            None, "insufficient", "unknown",
            "Insufficient Evidence - not enough news content was provided to verify.",
            [entry("info", "Insufficient evidence",
                   "Supply a headline, article text, news URL, screenshot or PDF.")],
            ["Provide more of the article or the original URL."],
            {"type": "News", "verdict": "insufficient",
             "verdict_label": "❓ Insufficient Evidence", "confidence": 0,
             "main_claim": combined[:220], "sources": [], "entities": {},
             "search_queries": [],
             "explanation": "Not enough content was provided for any cross-check.",
             "network_note": ""})

    # 2. Claim + entities + headline quality -------------------------------------
    claim = _extract_main_claim(extracted_headline, content)
    entities = _extract_news_entities(extracted_headline, content)

    clickbait, misleading, missing = _detect_headline_quality(extracted_headline, content)
    if clickbait:
        reasons.append(entry("danger", "Clickbait headline patterns",
                             "Matches known formulas: %s." % ", ".join(clickbait[:4])))
    for m in misleading:
        reasons.append(entry("warning", "Misleading headline", m))
    for m in missing:
        reasons.append(entry("warning", "Missing context", m))
    if not (clickbait or misleading or missing):
        reasons.append(entry("success", "Headline looks factual",
                             "No clickbait, sensational or missing-context signals."))

    # 3. Auto-generate targeted search queries ------------------------------------
    queries = _build_search_queries(claim["claim"], extracted_headline, entities, content)

    # 4. Gather evidence candidates (feeds + live trusted-domain search) ----------
    candidates, seen_urls = [], set()
    feed_items = _fetch_feed_titles()
    for it in feed_items:
        key = it.get("link") or it.get("title")
        if key and key not in seen_urls:
            seen_urls.add(key)
            candidates.append({"title": it.get("title", ""), "url": it.get("link", ""),
                               "source": it.get("source", ""),
                               "published": it.get("published", ""),
                               "origin": "feed", "snippet": ""})

    search_ok = False
    for q in queries:
        hits = _search_news_web(q)
        if hits:
            search_ok = True
        for h in hits:
            key = h.get("url") or h.get("title", "")
            if key and key not in seen_urls:
                seen_urls.add(key)
                candidates.append({"title": h.get("title", ""), "url": h.get("url", ""),
                                   "source": h.get("source", "") or _hostname_label(h.get("url", "")),
                                   "published": "", "origin": "search",
                                   "snippet": h.get("snippet", "")})

    live_disabled = not current_app.config.get("LIVE_NETWORK", True)
    offline = live_disabled or (not feed_items and not search_ok)

    # 5. Compare every candidate against the claim --------------------------------
    sources, supporting, contradicting, related = [], 0, 0, 0
    best_sim, best_overlap = 0.0, 0.0
    max_contradict_sim = 0.0
    body_budget = 8
    for cand in candidates:
        page = None
        if cand.get("url") and body_budget > 0:
            page = _article_page(cand.get("url"))
            if page and page.get("text"):
                body_budget -= 1
        body_text = (page.get("text") if page else "") or ""
        published = (cand.get("published") or (page.get("published") if page else "") or "")
        title = cand.get("title") or (page.get("title") if page else "") or ""
        cmp = _compare_claim_evidence(claim["claim"], entities, title, body_text, published)
        category = cmp["category"]
        if category == "support":
            supporting += 1
        elif category == "contradict":
            contradicting += 1
            max_contradict_sim = max(max_contradict_sim, cmp["sim"])
        elif category == "related":
            related += 1
        best_sim = max(best_sim, cmp["sim"])
        best_overlap = max(best_overlap, cmp["entity_overlap"])
        if category != "none":
            sources.append({
                "title": (title or cand.get("title", ""))[:140],
                "link": cand.get("url", ""), "source": cand.get("source", ""),
                "published": published, "snippet": cand.get("snippet", "")[:220],
                "similarity": int(round(cmp["sim"] * 100)),
                "title_similarity": int(round(cmp["title_sim"] * 100)),
                "body_similarity": int(round(cmp["body_sim"] * 100)),
                "entity_overlap": int(round(cmp["entity_overlap"] * 100)),
                "date_consistent": cmp["date_consistent"], "support": category})
        if len(sources) >= 14:
            break

    # 6. Verdict + confidence (evidence only) --------------------------------------
    labels = {
        "verified": "✅ Verified",
        "partially_verified": "⚠️ Partially Verified",
        "insufficient": "❓ Insufficient Evidence",
        "contradicted": "❌ Contradicted by Reliable Sources",
    }

    if offline:
        verdict, status, risk = "insufficient", "insufficient", "unknown"
        confidence = 15
        score = None
        summary = "Unable to verify because live internet search is unavailable."
        network_note = ("Live internet search was disabled or unreachable for "
                        "this scan, so no trusted source could be cross-checked.")
    elif contradicting and contradicting >= supporting:
        verdict, status, risk = "contradicted", "verified", "high"
        confidence = _news_contradiction_confidence(
            contradicting, max_contradict_sim, best_overlap, bool(clickbait))
        score = max(5, 100 - confidence)
        summary = ("Contradicted by Reliable Sources - %d trusted report(s) report "
                   "the opposite of this claim." % contradicting)
        network_note = ""
    elif supporting >= 2:
        verdict, status, risk = "verified", "verified", "low"
        confidence = _news_confidence(supporting, best_sim, best_overlap,
                                      related > 0, bool(clickbait), len(misleading))
        score = confidence
        if confidence < 80:
            risk = "medium"
        summary = ("Verified - the claim matches %d trusted, primary source report(s)."
                   % supporting)
        network_note = ""
    elif supporting == 1:
        verdict, status, risk = "partially_verified", "verified", "medium"
        confidence = _news_confidence(supporting, best_sim, best_overlap,
                                      related > 0, bool(clickbait), len(misleading))
        score = confidence
        summary = ("Partially Verified - some supporting reports exist but the "
                   "evidence is not conclusive for a full confirmation.")
        network_note = ""
    else:
        verdict, status, risk = "insufficient", "insufficient", "unknown"
        confidence = 35 if related else 15
        score = None
        summary = ("Insufficient Evidence - no trusted source confirmed or "
                   "contradicted this claim, so no confident verdict is possible.")
        network_note = (("Live search reached trusted outlets but none matched "
                         "this claim closely enough (%d related report(s) found)."
                         % related) if search_ok else "")

    if not offline and sources:
        for s in sources:
            sev = {"support": "success", "contradict": "danger"}.get(s["support"], "info")
            title = {"support": "Supporting report",
                     "contradict": "Contradicting report"}.get(s["support"], "Related report")
            reasons.append(entry(sev, title,
                                 "%s (%.0f%% similar)%s"
                                 % (s["source"] or s["title"], s["similarity"],
                                    " - %s" % s["published"] if s["published"] else "")))

    if offline:
        reasons.append(entry("warning", "Live verification unavailable",
                             "Unable to verify because live internet search is "
                             "unavailable."))
    else:
        if supporting:
            reasons.append(entry("success", "Confirmed by trusted sources",
                                 "%d trusted report(s) align with this claim."
                                 % supporting))
        if contradicting:
            reasons.append(entry("danger", "Contradicted by trusted sources",
                                 "%d trusted report(s) report the opposite."
                                 % contradicting))
        if not sources:
            reasons.append(entry("info", "No close trusted-source match",
                                 "Live search found %d candidate article(s) but "
                                 "none matched the claim closely enough."
                                 % len(candidates)))

    # 7. Explanation (rule-based + optional AI prose AFTER the verdict) ------------
    explanation = _explain_verdict(verdict, supporting, contradicting, related,
                                   sources, confidence, offline=offline)
    ai = ""
    if not offline:
        ai = _llm_news_explanation(claim["claim"], labels[verdict], supporting,
                                   contradicting, [s["source"] for s in sources])

    # 8. Suggestions ---------------------------------------------------------------
    if verdict == "verified":
        suggestions = ["Check the publication date - old or re-circulated news is often misleading.",
                       "Bookmark the supporting articles above as your sources."]
    elif verdict == "partially_verified":
        suggestions = ["Cross-check the unconfirmed details against a second trusted source before sharing.",
                       "Look for another primary report covering the same event."]
    elif verdict == "contradicted":
        suggestions = ["Do not share this claim - trusted outlets report the opposite.",
                       "Read the contradicting articles linked above for the facts."]
    else:
        suggestions = ["Retry when live internet search is available, or provide the original article URL.",
                       "Compare the claim manually against two trusted primary sources."]

    meta = {
        "type": "News",
        "verdict": verdict,
        "verdict_label": labels[verdict],
        "confidence": confidence,
        "main_claim": claim["claim"],
        "extracted_headline": extracted_headline or claim["headline"],
        "headline": extracted_headline or claim["headline"],
        "publication_date": publication_date or "",
        "source_domain": source_domain,
        "clickbait": bool(clickbait),
        "misleading": misleading[:4],
        "misleading_count": len(misleading),
        "missing_context": missing[:4],
        "missing_context_count": len(missing),
        "entities": entities,
        "search_queries": queries,
        "supporting_count": supporting,
        "contradicting_count": contradicting,
        "related_count": related,
        "sources": sources,
        "ai_explanation": ai or "",
        "explanation": explanation,
        "network_note": network_note,
        "offline": offline,
    }
    return make_result(score, status, risk, summary, reasons, suggestions, meta)


# --------------------------------------------------------------------------- #
#  Claim checker
# --------------------------------------------------------------------------- #

# Optional LLM verification (OpenAI-compatible chat completions). Disabled when
# no API key is configured; the claim checker then falls back to a keyless
# Wikipedia search or an honest "insufficient evidence" result.
CLAIM_LLM_URL = "https://api.openai.com/v1/chat/completions"
CLAIM_LLM_MODEL = os.environ.get("TRUSTLENS_LLM_MODEL", "gpt-4o-mini")


def _llm_verify_claim(claim):
    """Ask a configured LLM to fact-check a claim. Returns dict or None."""
    key = os.environ.get("TRUSTLENS_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key or not HAS_REQUESTS:
        return None
    try:
        r = requests.post(CLAIM_LLM_URL, headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
        }, json={
            "model": CLAIM_LLM_MODEL,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system",
                 "content": "You are a careful fact-checker. Answer with strict JSON only: "
                            "{\"verdict\":\"true\"|\"false\"|\"unverified\",\"confidence\":0.0..1.0,"
                            "\"reason\":\"one or two sentences\",\"source\":\"source name or empty string\"}. "
                            "Use \"unverified\" when you are not reasonably certain."},
                {"role": "user", "content": claim},
            ],
        }, timeout=15)
        if r.status_code != 200:
            return None
        obj = json.loads(r.json()["choices"][0]["message"]["content"])
        verdict = str(obj.get("verdict", "unverified")).lower()
        if verdict not in ("true", "false", "unverified"):
            verdict = "unverified"
        try:
            conf = min(1.0, max(0.0, float(obj.get("confidence", 0))))
        except (TypeError, ValueError):
            conf = 0.0
        return {"verdict": verdict, "confidence": conf,
                "reason": str(obj.get("reason", ""))[:300],
                "source": str(obj.get("source", ""))[:200] or "LLM fact-check",
                "method": "AI query check"}
    except Exception:
        return None


def _wikipedia_verify(claim):
    """
    Keyless web-search fallback. Searches Wikipedia abstracts for the claim's
    subject and returns a best-effort verdict dict, or None when the live check
    cannot run or nothing relevant is found.
    """
    if not (HAS_REQUESTS and current_app.config.get("LIVE_NETWORK", True)):
        return None
    try:
        r = requests.get("https://en.wikipedia.org/w/api.php", params={
            "action": "query", "format": "json", "list": "search",
            "srsearch": claim, "srlimit": 3,
            "prop": "extracts", "exintro": 1, "explaintext": 1,
        }, timeout=10, headers={"User-Agent": "TrustLens-Verifier/1.0 (educational)"})
        if r.status_code != 200:
            return None
        hits = r.json().get("query", {}).get("search", [])
        if not hits:
            return None
        best, best_sim = None, 0.0
        for h in hits[:3]:
            snippet = re.sub(r"<[^>]+>", "", h.get("snippet", ""))
            snippet = snippet.replace("&quot;", '"').replace("&#160;", " ")
            text = (h.get("title", "") + " " + snippet).lower()
            sim = max(_dice_coeff(_claim_tokens(claim), _claim_tokens(text)),
                      _jaccard(_claim_tokens(claim), _claim_tokens(text)))
            if sim > best_sim:
                best_sim, best = sim, {"title": h.get("title", ""), "snippet": snippet}
        if not best or best_sim < 0.18:
            return None
        lower_snip = best["snippet"].lower()
        negated = bool(re.search(
            r"\b(not|no|never|myth|false|incorrect|falsely|wrong|disproved|debunked|"
            r"does not|do not|is not|are not|cannot|can not)\b", lower_snip))
        if negated:
            verdict, reason = "false", ("Wikipedia disputes this: \"%s\"." % best["snippet"][:200])
        else:
            verdict, reason = "true", ("Wikipedia supports this: \"%s\"." % best["snippet"][:200])
        conf = min(0.8, 0.5 + best_sim)
        return {"verdict": verdict, "confidence": conf,
                "reason": reason,
                "source": "https://en.wikipedia.org/wiki/%s" % best["title"].replace(" ", "_"),
                "method": "Wikipedia search heuristic"}
    except Exception:
        return None


def _polarity_flip(claim, doc):
    """True when claim and doc assert opposite polarities on the same content."""
    neg = r"\b(?:not|no|never|without|cannot|can't|doesn't|don't|isn't|aren't|won't|wouldn't)\b"
    c_neg = bool(re.search(neg, claim.lower()))
    d_neg = bool(re.search(neg, doc.lower()))
    return c_neg != d_neg


def _verify_claim_web(claim):
    """Run the fallback verification chain; returns a dict or None."""
    return _llm_verify_claim(claim) or _wikipedia_verify(claim)


def claim_checker(claim):
    from models import KnowledgeItem
    claim = (claim or "").strip()
    if len(claim) < 8:
        return make_result(None, "insufficient", "unknown",
                           "The claim is too short to evaluate.",
                           [entry("info", "Insufficient evidence", "Enter a full claim statement.")],
                           ["State the claim as a complete sentence."])
    items = KnowledgeItem.query.all()
    if not items:
        return make_result(None, "insufficient", "unknown",
                           "The evidence knowledge base is empty.",
                           [entry("info", "Insufficient evidence",
                                  "No knowledge-base entries exist to compare against.")],
                           ["Try the claim again once the database is seeded."])
    docs = [i.claim for i in items]
    claim_tokens = set(_claim_tokens(claim))
    sims = claim_similarity(claim, docs)
    idx, sim = max(enumerate(sims), key=lambda x: x[1])
    matched = items[idx]
    # Require real subject/content overlap: a high score driven only by generic
    # bigrams (e.g. "makes you") is not a match.
    content_overlap = len(claim_tokens & set(_claim_tokens(matched.claim)))
    if sim >= 0.30 and content_overlap >= 2:
        flip = _polarity_flip(claim, matched.claim)
        verdict = matched.verdict
        if flip:
            # The claim says the opposite of what the matched evidence asserts,
            # so it should be scored as the inverse of the stored verdict.
            verdict = "false" if verdict == "true" else "true"
        status = "verified"
        label = "Likely True" if verdict == "true" else "Likely False"
        if flip:
            score = 80 if verdict == "true" else 20
            match_text = ("The claim contradicts a matched knowledge-base claim "
                          "(%.0f%% similarity, opposite polarity)." % (sim * 100))
        else:
            score = 90 if verdict == "true" else 15
            match_text = "Matched a knowledge-base claim with %.0f%% similarity." % (sim * 100)
        confidence = int(round(min(sim, 1.0) * 100))
        reasons = [
            entry("success" if verdict == "true" else "danger", label, match_text),
            entry("info", "Evidence", (matched.evidence or "No additional evidence recorded.")[:300]),
        ]
        if matched.source:
            reasons.append(entry("info", "Source", matched.source))
        return make_result(score, status, "low" if verdict == "true" else "high",
                           "Claim matched existing knowledge-base evidence.",
                           reasons, ["Review the linked evidence before sharing."],
                           {"type": "Claim", "confidence": confidence, "method": "knowledge base"})

    # Local match too weak -> fall back to a live web / AI verification check so a
    # real-world fact is not left as a bare "Unknown".
    best_sim_pct = int(round(sim * 100))
    web = _verify_claim_web(claim)
    if web and web.get("verdict") in ("true", "false"):
        verdict = web["verdict"]
        label = "Likely True" if verdict == "true" else "Likely False"
        confidence = int(round(web.get("confidence", 0.5) * 100))
        if verdict == "true":
            score, risk = 70 + int(20 * web.get("confidence", 0.5)), "low"
        else:
            score, risk = max(0, 20 - int(10 * web.get("confidence", 0.5))), "high"
        reasons = [
            entry("success" if verdict == "true" else "danger", label,
                  "Local match was only %d%% - verified via %s."
                  % (best_sim_pct, web.get("method", "live web check"))),
            entry("info", "Web evidence", (web.get("reason") or "No explanation returned.")[:300]),
            entry("info", "Source", web.get("source", "")),
        ]
        return make_result(score, "verified", risk,
                           "Claim verified via a live external check.",
                           reasons, ["Cross-check with at least one more trusted, primary source."],
                           {"type": "Claim", "confidence": confidence,
                            "method": web.get("method", "web check")})
    if web:
        return make_result(None, "insufficient", "unknown",
                           "No confident verdict after a live web check.",
                           [entry("info", "Insufficient evidence",
                                  "Best local match was %d%% and the live check could not reach a "
                                  "verdict: %s" % (best_sim_pct, (web.get("reason") or "no conclusive evidence"))),
                            entry("info", "Web source", web.get("source", "none"))],
                           ["Cross-check the claim against trusted, primary sources and retry."])
    return make_result(None, "insufficient", "unknown",
                       "No entry in the evidence base is similar enough to judge this claim.",
                       [entry("info", "Insufficient evidence",
                              "Best match was %d%% similar, below the decision threshold, and live "
                              "verification was unavailable." % best_sim_pct)],
                       ["Enable live network checks (or set an LLM API key), or rephrase the claim."])


# --------------------------------------------------------------------------- #
#  Product ingredient scanner
# --------------------------------------------------------------------------- #

def ingredient_scanner(file_path, file_name=""):
    if not file_path:
        return make_result(None, "insufficient", "unknown",
                           "No label image was uploaded.",
                           [entry("info", "Insufficient evidence", "Upload the back label of the product.")],
                           ["Upload a clear photo of the ingredients list."])
    reasons, suggestions = [], []
    img = image_scanner(file_path, file_name)
    meta = img["meta"] if isinstance(img["meta"], dict) else {}
    ocr_text = meta.get("ocr_text", "") or ""
    ocr_conf = meta.get("ocr_confidence")
    for r in img["reasons"]:
        if r["severity"] in ("danger", "warning"):
            reasons.append(r)

    # Fallback: blurry, dark or unreadable labels must NOT get a default high score.
    low_quality = (not ocr_text.strip()
                   or (ocr_conf is not None and ocr_conf < 0.40)
                   or len(ocr_text.strip()) < 5)
    if low_quality:
        return make_result(None, "insufficient", "unknown",
                           LOW_QUALITY_INGREDIENT_MSG,
                           reasons + [entry("info", "Low image quality",
                                            "OCR could not read the ingredient list reliably, so no "
                                            "score is assigned.")],
                           ["Retake the photo under even lighting with the label in focus and "
                            "parallel to the camera."],
                           {"type": "Ingredients", "low_quality": True,
                            "ocr_confidence": ocr_conf})

    reasons.append(entry("success", "Label text extracted",
                         "OCR read %d characters from the label (mean confidence %s)."
                         % (len(ocr_text), ("%.2f" % ocr_conf) if ocr_conf is not None else "n/a")))

    # Product type & usage-caution detection ---------------------------------------
    # Category detection runs BEFORE ingredient analysis. Any hair/skin/cosmetic
    # keyword forces a non-edible verdict, so overlap ingredients (starch, argan
    # oil, aloe vera, ...) can never make a cosmetic product look like food.
    # Food markers ("nutrition facts", "ready-to-eat", ...) classify edible items.
    category, is_edible, caution_flags = _detect_product_category(ocr_text.lower())
    if is_edible is False:
        banner, banner_type = NON_EDIBLE_BANNER, "non-edible"
    elif is_edible is True:
        banner, banner_type = EDIBLE_BANNER, "edible"
    else:
        banner, banner_type = None, None
    if banner_type == "non-edible":
        reasons.append(entry("danger", "Non-edible cosmetic product - not for ingestion",
                             NON_EDIBLE_BANNER))
    elif banner_type == "edible":
        reasons.append(entry("success", "Edible food product confirmed",
                             EDIBLE_BANNER))
    if category != "Unidentified":
        reasons.append(entry("info", "Product category identified",
                             "%s." % category))

    # Flexible ingredient extraction: fuzzy header -> fallback term lines.
    region, region_method, region_header = _extract_ingredient_region(ocr_text)
    if region_method == "header":
        reasons.append(entry("success", "Ingredient section located",
                             "Fuzzy header '%s' matched the ingredients list." % region_header))
    elif region_method == "fallback":
        reasons.append(entry("info", "Ingredient terms extracted",
                             "No ingredients header found - extracted the comma-separated "
                             "ingredient terms from the label text."))
    tokens = _parse_ingredients(region)
    if not tokens:
        return make_result(None, "insufficient", "unknown",
                           LOW_QUALITY_INGREDIENT_MSG,
                           reasons + [entry("info", "Low image quality",
                                            "The extracted text contained no usable ingredient entries.")],
                           ["Retake the photo with the label in focus and parallel to the camera."],
                           {"type": "Ingredients", "low_quality": True,
                            "ocr_confidence": ocr_conf,
                            "product_category": category, "is_edible": is_edible,
                            "caution_flags": caution_flags, "caution_banner": banner,
                            "edible_banner": banner if banner_type == "edible" else None,
                            "banner_type": banner_type})

    safe, moderate, high, unknown = _classify_ingredients(tokens)
    if not (safe or moderate or high):
        return make_result(None, "insufficient", "unknown",
                           "No known ingredients could be identified from the label.",
                           reasons + [entry("info", "Insufficient evidence",
                                            "The extracted text (%s) did not match the safety database."
                                            % ", ".join(unknown[:8]) or "No readable entries.")],
                           ["The photo may not show an ingredients list, or the text is too faint "
                            "to read reliably."],
                           {"type": "Ingredients", "ocr_text": ocr_text[:2000],
                            "low_quality": True, "unknown_ingredients": unknown[:25],
                            "product_category": category, "is_edible": is_edible,
                            "usage_context": ("topical" if is_edible is False
                                              else ("edible" if is_edible else "unknown")),
                            "caution_flags": caution_flags, "caution_banner": banner,
                            "edible_banner": banner if banner_type == "edible" else None,
                            "banner_type": banner_type})

    severe_hits = [i for i in high if i["name"] in SEVERE_INGREDIENTS]
    score = _ingredient_score(safe, moderate, high, severe_hits)

    for item in high[:8]:
        reasons.append(entry("danger", "High-risk ingredient: %s" % item["name"],
                             item["why"], "−25 points"))
    if len(high) > 8:
        reasons.append(entry("info", "Additional high-risk ingredients",
                             "%d more high-risk item(s) also detected." % (len(high) - 8)))
    for item in moderate[:8]:
        reasons.append(entry("warning", "Moderate-risk ingredient: %s" % item["name"],
                             item["why"], "−10 points"))
    if len(moderate) > 8:
        reasons.append(entry("info", "Additional moderate-risk ingredients",
                             "%d more moderate-risk item(s) also detected." % (len(moderate) - 8)))
    for item in safe[:8]:
        reasons.append(entry("success", "Safe ingredient: %s" % item["name"], item["why"]))
    if len(safe) > 8:
        reasons.append(entry("info", "Additional safe ingredients",
                             "%d more safe ingredient(s) were also identified." % (len(safe) - 8)))
    if unknown:
        reasons.append(entry("info", "Ingredients not in database",
                             "%d item(s) could not be classified: %s."
                             % (len(unknown), ", ".join(unknown[:8]))))

    summary = ("Safety Trust Score %d/100 - %d high-risk, %d moderate-risk and %d safe ingredient(s) "
               "identified from %d ingredient(s) detected."
               % (score, len(high), len(moderate), len(safe), len(safe) + len(moderate) + len(high) + len(unknown)))
    if is_edible is False:
        summary += " Topical-only non-edible product - do not consume or eat."
    elif is_edible is True:
        summary += " This is an edible food product."
    suggestions = [
        "High-risk ingredients are not automatically harmful - consider quantity and frequency of use.",
        "Consult a healthcare professional for personal concerns.",
    ]
    if banner_type == "non-edible":
        suggestions.insert(0, "This product is for EXTERNAL / TOPICAL use only - never consume or eat it.")
        suggestions.append("Even GRAS ingredients can irritate sensitive skin - patch test new products.")
        suggestions.append("Consult a dermatologist for personal skin-care concerns.")
    elif banner_type == "edible":
        suggestions.insert(0, "This is an edible food/beverage item - review portion sizes and overall diet.")
        suggestions.append("Food additives are generally safe within regulatory limits - variety matters.")
    return make_result(score, "verified", risk_for(score), summary, reasons, suggestions,
                       {"type": "Ingredients",
                        "ocr_text": ocr_text[:2000],
                        "ocr_confidence": ocr_conf,
                        "ingredient_count": len(tokens),
                        "extraction_method": region_method,
                        "product_category": category,
                        "is_edible": is_edible,
                        "usage_context": ("topical" if is_edible is False
                                          else ("edible" if is_edible else "unknown")),
                        "caution_flags": caution_flags,
                        "caution_banner": banner if banner_type == "non-edible" else None,
                        "edible_banner": banner if banner_type == "edible" else None,
                        "banner_type": banner_type,
                        "safe_ingredients": [i["name"] for i in safe],
                        "moderate_ingredients": [{"name": i["name"], "why": i["why"]} for i in moderate],
                        "risky_ingredients": [{"name": i["name"], "why": i["why"]} for i in high],
                        "severe_ingredients": [i["name"] for i in severe_hits],
                        "unknown_ingredients": unknown[:25],
                        "low_quality": False,
                        "matched": {"safe": [i["name"] for i in safe],
                                    "moderate": [i["name"] for i in moderate],
                                    "high": [i["name"] for i in high],
                                    "unknown": unknown}})


# --------------------------------------------------------------------------- #
#  QR scanner
# --------------------------------------------------------------------------- #

def _parse_upi_payload(payload):
    """Parse a `upi://pay?<query>` deep link into a param dict.

    Returns a dict of URL-decoded UPI parameters (lower-cased keys) when the
    payload is a UPI payment QR, otherwise None. Every verdict downstream is
    built from these parameters, never from a fixed value.
    """
    text = (payload or "").strip()
    if not UPI_QR_SCHEME_RE.match(text):
        return None
    query = UPI_QR_SCHEME_RE.sub("", text, count=1)
    params = {}
    for part in query.split("&"):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        params.setdefault(key, urllib.parse.unquote_plus(value.strip()))
    return params


def _validate_upi_id(upi_id):
    """Validate a UPI payee address.

    Returns (valid, errors, warnings) where `valid` reflects the structural
    regex check and `warnings` lists recognition/placeholder concerns that do
    not invalidate the ID by themselves.
    """
    upi_id = (upi_id or "").strip()
    if not upi_id:
        return False, ["The mandatory 'pa' (payee UPI ID) parameter is missing "
                       "from the QR - it cannot route a payment."], []
    if not re.fullmatch(UPI_ID_STRICT_RE, upi_id):
        return False, ["'%s' is not a structurally valid UPI ID (expected "
                       "localpart@handle)." % upi_id], []
    identifier, _, handle = upi_id.partition("@")
    warnings = []
    if handle.lower() not in UPI_HANDLES:
        warnings.append("The payee handle '@%s' is not in the known UPI PSP "
                        "handle list - confirm the payee independently." % handle)
    placeholder = _flag_upi(upi_id)
    if placeholder:
        warnings.append(placeholder[1])
    return True, [], warnings


def _verify_upi_qr(payload):
    """Full evidence-based verification of a UPI payment QR payload.

    Returns a verdict dict {score, status, summary, reasons, suggestions,
    meta, verdict} used by qr_scanner. Valid QRs get "Valid UPI QR", any
    structural failure or suspicious signal gets "Suspicious UPI QR" with the
    exact reasons listed as evidence.
    """
    params = _parse_upi_payload(payload) or {}
    reasons, suggestions = [], []
    suspicious_flags = []
    score = 50  # neutral baseline for a decodable UPI deep link

    upi_id = params.get("pa", "")
    meta = {
        "upi_pa": upi_id,
        "upi_pn": params.get("pn", ""),
        "upi_am": params.get("am", ""),
        "upi_cu": (params.get("cu") or "").upper(),
        "upi_tn": params.get("tn", ""),
        "upi_tr": params.get("tr", ""),
    }

    valid, errors, warnings = _validate_upi_id(upi_id)
    if not upi_id:
        for e in errors:
            reasons.append(entry("danger", "Mandatory field missing", e, "−30 points"))
        score -= 30
        suspicious_flags.append("missing pa")
    elif not valid:
        for e in errors:
            reasons.append(entry("danger", "Invalid UPI ID", e, "−25 points"))
        score -= 25
        suspicious_flags.append("invalid pa format")
    else:
        reasons.append(entry("success", "UPI ID format valid",
                             "Payee address '%s' matches the standard UPI "
                             "localpart@handle format." % upi_id))
        score += 20
        if upi_id.partition("@")[2].lower() in UPI_HANDLES:
            reasons.append(entry("success", "Recognised PSP handle",
                                 "The payee handle '@%s' is a known UPI payments "
                                 "provider." % upi_id.partition("@")[2]))
            score += 5
        else:
            reasons.append(entry("warning", "Unrecognised PSP handle",
                                 "The payee handle '@%s' is not in the known UPI "
                                 "PSP list." % upi_id.partition("@")[2]))
            suspicious_flags.append("unknown handle")
    for w in warnings:
        reasons.append(entry("warning", "UPI ID caution", w, "−10 points"))
        score -= 10
        suspicious_flags.append("placeholder UPI ID")

    am_raw = params.get("am", "")
    if am_raw:
        try:
            amount = float(am_raw)
            if amount > 0:
                reasons.append(entry("info", "Amount requested",
                                     "The QR asks the payer to send %s %s."
                                     % (am_raw, meta["upi_cu"] or "INR")))
                if amount < 1:
                    reasons.append(entry("warning", "Unusually small amount",
                                         "%s is a trivial sum - a pattern seen in "
                                         "QR phishing probes." % am_raw, "−5 points"))
                    score -= 5
                else:
                    score += 5
            else:
                reasons.append(entry("warning", "Non-positive amount",
                                     "'%s' is not a positive amount." % am_raw,
                                     "−5 points"))
                score -= 5
        except ValueError:
            reasons.append(entry("warning", "Malformed amount",
                                 "'%s' is not a valid numeric amount." % am_raw,
                                 "−5 points"))
            score -= 5
    else:
        reasons.append(entry("info", "No fixed amount",
                             "No 'am' parameter - the payer picks the amount at "
                             "payment time, so there is no requested sum."))

    cu = meta["upi_cu"] or "INR"
    if cu != "INR":
        reasons.append(entry("warning", "Non-INR currency",
                             "Currency is '%s' - UPI QRs normally denominate in "
                             "INR." % cu, "−5 points"))
        score -= 5
        suspicious_flags.append("non-INR currency")
    else:
        reasons.append(entry("success", "Currency is INR",
                             "The QR is denominated in Indian Rupees."))

    pn = params.get("pn", "")
    if pn:
        if pn.strip().lower() in PLACEHOLDER_UPI_LABELS:
            reasons.append(entry("warning", "Generic payee name",
                                 "'%s' looks like a template/demo account name."
                                 % pn, "−10 points"))
            score -= 10
            suspicious_flags.append("placeholder payee name")
        else:
            reasons.append(entry("info", "Payee name present",
                                 "Account/Payee name: %s" % pn[:80]))
            score += 5
    else:
        reasons.append(entry("info", "No payee name",
                             "No 'pn' (payee name) parameter - less context to "
                             "judge the legitimacy of the account."))

    tn = params.get("tn", "")
    if tn:
        hits = [k for k in UPI_SUSPICIOUS_NOTE_KEYWORDS if k in tn.lower()]
        if hits:
            reasons.append(entry("danger", "Suspicious transaction note",
                                 "The note '%s' contains scam-style wording: %s."
                                 % (tn[:80], ", ".join(hits[:4])), "−20 points"))
            score -= 20
            suspicious_flags.append("suspicious transaction note")
        else:
            reasons.append(entry("info", "Transaction note",
                                 "Note embedded in the QR: %s" % tn[:80]))
    if params.get("tr"):
        reasons.append(entry("info", "Transaction reference",
                             "A transaction reference (tr) is embedded: %s"
                             % params["tr"][:40]))

    score = max(0, min(100, score))
    verdict = "Suspicious UPI QR" if suspicious_flags else "Valid UPI QR"
    if verdict == "Valid UPI QR":
        summary = ("Valid UPI QR - the payee address is structurally valid, the "
                   "handle is recognised and no suspicious signals were found.")
    else:
        summary = ("Suspicious UPI QR - %d problem(s): %s."
                   % (len(suspicious_flags), ", ".join(suspicious_flags)))
        suggestions.append("Confirm the payee identity before paying - call the "
                           "merchant on their verified phone number.")
        suggestions.append("Never pay 'processing fees' or rewards-related UPI "
                           "collect requests from unknown QRs.")
    meta["upi_validation"] = "valid" if valid else "invalid"
    meta["upi_verdict"] = verdict
    return {"score": score, "status": "verified", "summary": summary,
            "reasons": reasons, "suggestions": suggestions, "meta": meta,
            "verdict": verdict}


def _check_ssl_cert(host, timeout=8):
    """Return (True|False|None, human detail) for the host's TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                if not cert:
                    return None, "TLS handshake succeeded but no certificate metadata was returned."
                not_after = cert.get("notAfter")
                if not not_after:
                    return True, "TLS certificate presented; expiry date not disclosed."
                expire = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after),
                                                timezone.utc)
                days = (expire - datetime.now(timezone.utc)).days
                if days < 0:
                    return False, "TLS certificate expired %d days ago." % abs(days)
                issuer = dict(x[0] for x in cert.get("issuer", [])).get(
                    "organizationName", "unknown CA")
                return True, ("Valid TLS certificate from '%s' valid until %s "
                              "(%d days remaining)."
                              % (issuer, expire.strftime("%d %b %Y"), days))
    except ssl.SSLCertVerificationError as e:
        return False, "SSL certificate verification failed: %s" % e
    except ssl.SSLError as e:
        return False, "SSL error during handshake: %s" % e
    except socket.timeout:
        return None, "TLS connection to %s timed out." % host
    except socket.gaierror:
        return None, "Host '%s' did not resolve." % host
    except (OSError, ConnectionError) as e:
        return None, "TLS connection to %s failed: %s" % (host, e)


SAFE_BROWSING_ENDPOINT = ("https://safebrowsing.googleapis.com/"
                          "v4/threatMatches:find")


def _safe_browsing_check(url):
    """Optional Google Safe Browsing lookup. Returns a dict or None."""
    key = current_app.config.get("SAFE_BROWSING_KEY") or \
        os.environ.get("TRUSTLENS_SAFEBROWSING_KEY")
    if not key:
        return {"threat": None, "detail": "Google Safe Browsing API key not "
                                          "configured - lookup skipped."}
    if not HAS_REQUESTS:
        return {"threat": None, "detail": "Google Safe Browsing check skipped - "
                                          "requests library unavailable."}
    try:
        body = {"client": {"clientId": "trustlens", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                    "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]}}
        r = requests.post("%s?key=%s" % (SAFE_BROWSING_ENDPOINT, key),
                          json=body, timeout=8)
        if r.status_code == 200:
            matches = (r.json() or {}).get("matches") or []
            if matches:
                kinds = sorted({m.get("threatType") for m in matches})
                return {"threat": True, "detail": "Flagged as %s by Google Safe "
                                                  "Browsing." % ", ".join(kinds)}
            return {"threat": False, "detail": "No threats reported by Google "
                                               "Safe Browsing."}
        return {"threat": None, "detail": "Safe Browsing API returned HTTP %d."
                                          % r.status_code}
    except Exception:
        return {"threat": None, "detail": "Safe Browsing lookup failed (network "
                                          "or API error)."}


def _virustotal_check(url):
    """Optional VirusTotal URL reputation lookup. Returns a dict or None."""
    key = current_app.config.get("VIRUSTOTAL_KEY") or \
        os.environ.get("TRUSTLENS_VIRUSTOTAL_KEY")
    if not key:
        return {"malicious": None, "detail": "VirusTotal API key not configured "
                                             "- lookup skipped."}
    if not HAS_REQUESTS:
        return {"malicious": None, "detail": "VirusTotal check skipped - "
                                             "requests library unavailable."}
    try:
        headers = {"x-apikey": key}
        r = requests.post("https://www.virustotal.com/api/v3/urls",
                          headers=headers, data={"url": url}, timeout=10)
        if r.status_code != 200:
            return {"malicious": None, "detail": "VirusTotal submit returned "
                                                 "HTTP %d." % r.status_code}
        analysis_id = (r.json().get("data") or {}).get("id")
        if not analysis_id:
            return {"malicious": None, "detail": "VirusTotal returned no analysis id."}
        r2 = requests.get("https://www.virustotal.com/api/v3/analyses/%s"
                          % analysis_id, headers=headers, timeout=10)
        if r2.status_code != 200:
            return {"malicious": None, "detail": "VirusTotal analysis lookup "
                                                 "returned HTTP %d." % r2.status_code}
        stats = ((r2.json().get("data") or {}).get("attributes") or {}) \
            .get("stats") or {}
        mal = int(stats.get("malicious", 0))
        sus = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        if total == 0:
            return {"malicious": None, "detail": "VirusTotal has no scan results "
                                                 "for this URL yet."}
        if mal > 0 or sus > 0:
            return {"malicious": True, "detail": "VirusTotal: %d malicious, %d "
                                                 "suspicious out of %d engines."
                                                 % (mal, sus, total)}
        return {"malicious": False, "detail": "VirusTotal: 0 malicious out of "
                                              "%d engines." % total}
    except Exception:
        return {"malicious": None, "detail": "VirusTotal lookup failed (network "
                                             "or API error)."}


def _verify_qr_url(url):
    """Evidence-based verification of a URL QR destination.

    Checks HTTPS, TLS certificate validity, domain age (WHOIS) and, when API
    keys are configured, Google Safe Browsing / VirusTotal reputation. Every
    check produces an evidence entry; unavailable checks are reported as
    skipped rather than guessed.
    """
    url = (url or "").strip()
    reasons, suggestions = [], []
    parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower()
    score = 50
    meta = {"url": url, "domain": host}
    live = current_app.config.get("LIVE_NETWORK", True)

    is_flag, flag_reason = inspect_url(url)
    if is_flag:
        reasons.append(entry("danger", "Suspicious QR destination URL",
                             flag_reason, "−25 points"))
        score -= 25
    else:
        reasons.append(entry("success", "URL structure looks normal",
                             "HTTPS scheme and a common top-level domain."))
        score += 15

    if parsed.scheme == "http":
        reasons.append(entry("danger", "Unencrypted HTTP destination",
                             "The QR points to a plain-HTTP URL; data is sent "
                             "without encryption.", "−15 points"))
        score -= 15
    elif parsed.scheme == "https":
        reasons.append(entry("success", "HTTPS destination",
                             "The QR points to an HTTPS (encrypted) URL."))
        score += 5
    else:
        reasons.append(entry("warning", "Non-web scheme",
                             "The payload uses the '%s' scheme, not HTTPS."
                             % parsed.scheme, "−10 points"))
        score -= 10

    if host:
        if live:
            ssl_ok, ssl_detail = _check_ssl_cert(host)
            meta["ssl_status"] = ssl_detail
            if ssl_ok is True:
                reasons.append(entry("success", "TLS certificate valid", ssl_detail))
                score += 10
            elif ssl_ok is False:
                reasons.append(entry("danger", "TLS certificate problem",
                                     ssl_detail, "−20 points"))
                score -= 20
            else:
                reasons.append(entry("warning", "TLS certificate not verified",
                                     ssl_detail, "−5 points"))
                score -= 5
        else:
            reasons.append(entry("info", "Live TLS check skipped",
                                 "Network checks are disabled in this "
                                 "configuration."))

        if live and HAS_WHOIS:
            try:
                w = pywhois.whois(host)
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                if created:
                    days = (datetime.now(created.tzinfo) - created).days
                    meta["domain_age_days"] = days
                    if days < 30:
                        reasons.append(entry("warning", "Brand-new domain",
                                             "Registered only %d days ago - a "
                                             "trait of throwaway scam sites."
                                             % days, "−15 points"))
                        score -= 15
                    elif days < 365:
                        reasons.append(entry("info", "Young domain",
                                             "Registered %d days ago." % days))
                    else:
                        reasons.append(entry("success", "Established domain",
                                             "Registered %d days ago." % days))
                        score += 5
                else:
                    reasons.append(entry("info", "WHOIS returned no creation date",
                                         "Domain age could not be established."))
            except Exception:
                reasons.append(entry("info", "WHOIS unavailable",
                                     "Registration data could not be retrieved."))
        else:
            reasons.append(entry("info", "Domain age check skipped",
                                 "WHOIS lookup unavailable or network disabled."))

        if live:
            sb = _safe_browsing_check(url)
            if sb:
                if sb["threat"]:
                    reasons.append(entry("danger", "Google Safe Browsing flagged",
                                         sb["detail"], "−40 points"))
                    score -= 40
                else:
                    reasons.append(entry("success", "Google Safe Browsing clear",
                                         sb["detail"]))
            vt = _virustotal_check(url)
            if vt:
                if vt["malicious"]:
                    reasons.append(entry("danger", "VirusTotal flagged",
                                         vt["detail"], "−40 points"))
                    score -= 40
                else:
                    reasons.append(entry("info", "VirusTotal reputation",
                                         vt["detail"]))
        else:
            reasons.append(entry("info", "External reputation checks skipped",
                                 "Live network verification is disabled."))
    else:
        reasons.append(entry("danger", "No hostname",
                             "The payload does not contain a usable hostname.",
                             "−25 points"))
        score -= 25

    score = max(0, min(100, score))
    summary = ("URL QR verified: HTTPS/TLS, SSL certificate, domain age and "
               "reputation checks were evaluated.")
    return {"score": score, "status": "verified", "summary": summary,
            "reasons": reasons,
            "suggestions": ["Prefer QRs that point to https:// and verify the "
                            "exact domain spelling before paying or logging in."],
            "meta": meta, "verdict": "URL"}


def _decode_qr_robust(file_path):
    """Decode a QR code from an image with preprocessing + multi-rotation.

    Pipeline: grayscale -> contrast boost (CLAHE) -> adaptive threshold, each
    variant resized (2x when small) and tried at 0/90/180/270 degrees, decoded
    with OpenCV QRCodeDetector and then pyzbar. Returns (payload, method,
    attempts) or (None, None, attempts) after every backend has failed.
    """
    if not HAS_CV2:
        return None, None, []
    try:
        color = cv2.imread(file_path)
        if color is None:
            return None, None, []
        gray = cv2.cvtColor(color, cv2.COLOR_BGR2GRAY)
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        h, w = enhanced.shape
        if min(h, w) < 800:
            enhanced = cv2.resize(enhanced, (w * 2, h * 2),
                                  interpolation=cv2.INTER_CUBIC)
        binary = cv2.adaptiveThreshold(enhanced, 255,
                                       cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                       cv2.THRESH_BINARY, 31, 10)
    except Exception:
        return None, None, []
    rots = {0: None, 90: cv2.ROTATE_90_CLOCKWISE,
            180: cv2.ROTATE_180, 270: cv2.ROTATE_90_COUNTERCLOCKWISE}
    attempts = []
    for variant_label, img in (("contrast", enhanced), ("threshold", binary)):
        for angle, rot in rots.items():
            im = img if rot is None else cv2.rotate(img, rot)
            if HAS_CV2:
                attempts.append("%s/%ddeg/cv2" % (variant_label, angle))
                try:
                    data, _pts, _ = cv2.QRCodeDetector().detectAndDecode(im)
                except Exception:
                    data = ""
                if data:
                    return data, "OpenCV QRCodeDetector", attempts
            if HAS_PYZBAR:
                attempts.append("%s/%ddeg/pyzbar" % (variant_label, angle))
                try:
                    for res in zbar_decode(im):
                        if res.type == "QRCODE" and res.data:
                            return res.data.decode("utf-8", "replace"), "pyzbar", attempts
                except Exception:
                    pass
    return None, None, attempts

def qr_scanner(file_path):
    if not file_path:
        return make_result(None, "insufficient", "unknown",
                           "No QR code image was uploaded.",
                           [entry("info", "Insufficient evidence", "Upload an image containing a QR code.")],
                           ["Upload a clear photo of the QR code."])
    if not HAS_CV2 and not HAS_PYZBAR:
        return make_result(None, "error", "unknown",
                           "QR decoding library unavailable.",
                           [entry("danger", "Analysis unavailable",
                                  "Neither OpenCV nor pyzbar is installed.")],
                           ["Install requirements and retry."])
    # Robust decode: preprocessing, 4 rotations, OpenCV + pyzbar backends.
    data, method, attempts = _decode_qr_robust(file_path)
    if data is None:
        return make_result(None, "insufficient", "unknown",
                           "No QR code found in the image.",
                           [entry("info", "Insufficient evidence",
                                  "All %d decoding attempt(s) across the OpenCV and pyzbar "
                                  "backends failed to find a machine-readable QR payload."
                                  % max(len(attempts), 1))],
                           ["Ensure the QR code is fully visible, flat, in focus and well-lit."])
    # Display the decoded content, then run the appropriate verification engine.
    reasons = [entry("success", "QR code decoded",
                     "Payload: %s" % data[:120]),
               entry("info", "Decode method",
                     "Decoded via %s after %d attempt(s)." % (method, max(len(attempts), 1)))]

    # 1. UPI payment deep link -> full UPI verification engine.
    upi_params = _parse_upi_payload(data)
    if upi_params is not None:
        verdict = _verify_upi_qr(data)
        return make_result(verdict["score"], verdict["status"],
                           risk_for(verdict["score"]), verdict["summary"],
                           reasons + verdict["reasons"], verdict["suggestions"],
                           {"type": "QR", "qr_type": "UPI",
                            "payload": data[:200], **verdict["meta"]})

    # 2. Web destination -> HTTPS / TLS / domain age / reputation checks.
    if data.lower().startswith(("http://", "https://")):
        verdict = _verify_qr_url(data)
        return make_result(verdict["score"], verdict["status"],
                           risk_for(verdict["score"]), verdict["summary"],
                           reasons + verdict["reasons"], verdict["suggestions"],
                           {"type": "QR", "qr_type": "URL",
                            "payload": data[:200], **verdict["meta"]})

    # 3. Anything else -> generic text engine (with link inspection inside).
    text_result = text_scanner(data, scan_type="QR payload")
    for r in text_result["reasons"]:
        reasons.append(r)
    score = text_result["score"]
    return make_result(score, text_result["status"], risk_for(score),
                       "QR payload decoded and scored with the text verification engine.",
                       reasons, text_result["suggestions"],
                       {"type": "QR", "qr_type": "Text",
                        "payload": data[:200]})


# --------------------------------------------------------------------------- #
#  PDF report generation (ReportLab)
# --------------------------------------------------------------------------- #

def generate_pdf_report(scan_data, user_name, out_path):
    """Generate a professional PDF report from a scan result dict."""
    if not HAS_REPORTLAB:
        return False
    from reportlab.lib.enums import TA_CENTER
    styles = {
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=20,
                             leading=26, textColor=HexColor("#0f172a")),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13,
                             leading=18, textColor=HexColor("#334155"), spaceBefore=10),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10,
                               leading=15, textColor=HexColor("#1e293b")),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8,
                                leading=11, textColor=HexColor("#64748b")),
    }
    styles["center"] = ParagraphStyle("center", parent=styles["body"],
                                      alignment=TA_CENTER)
    score = scan_data.get("trust_score")
    risk = (scan_data.get("risk_level") or "unknown").upper()
    status = scan_data.get("status") or "verified"
    if score is None:
        score_text = "INSUFFICIENT EVIDENCE"
    else:
        score_text = "%d / 100" % score

    doc = SimpleDocTemplate(out_path, pagesize=A4,
                            rightMargin=20 * mm, leftMargin=20 * mm,
                            topMargin=20 * mm, bottomMargin=18 * mm,
                            title="TrustLens Verification Report")
    story = []
    story.append(Paragraph("TrustLens &mdash; Verification Report", styles["h1"]))
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#4f46e5")))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("User: %s" % (user_name or "Guest"), styles["body"]))
    story.append(Paragraph("Scan date: %s" % scan_data.get("created_at", "-"), styles["body"]))
    story.append(Paragraph("Scan type: %s" % scan_data.get("scan_type", "-"), styles["body"]))
    story.append(Spacer(1, 4 * mm))

    data = [
        ["Trust Score", score_text],
        ["Risk Level", risk],
        ["Status", status],
    ]
    table = Table(data, colWidths=[55 * mm, 100 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#eef2ff")),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#c7d2fe")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table)
    story.append(Spacer(1, 4 * mm))

    if scan_data.get("summary"):
        story.append(Paragraph("Analysis Summary", styles["h2"]))
        story.append(Paragraph(scan_data["summary"], styles["body"]))
    reasons = scan_data.get("reasons") or []
    if reasons:
        story.append(Paragraph("Reasons for this score", styles["h2"]))
        for r in reasons[:25]:
            icon = {"danger": "[!] ", "warning": "[/] ", "success": "[OK] ", "info": "[i] "}.get(r["severity"], "")
            impact = "  (impact: %s)" % r["impact"] if r.get("impact") else ""
            story.append(Paragraph("%s<strong>%s</strong>%s &mdash; %s"
                                   % (icon, r.get("title", ""), impact, r.get("text", "")),
                                   styles["body"]))
    suggestions = scan_data.get("suggestions") or []
    if suggestions:
        story.append(Paragraph("Suggestions", styles["h2"]))
        for s in suggestions:
            story.append(Paragraph("&bull; " + s, styles["body"]))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Generated by TrustLens - AI Based Information Verification System. "
                           "This report is a heuristic screening result, not an absolute guarantee.",
                           styles["small"]))
    try:
        doc.build(story)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Rate limiting (simple in-memory, per IP)
# --------------------------------------------------------------------------- #

_hits = {}


def allow_request(bucket, limit, window=60):
    """Return True if the request is within the rate limit for the bucket."""
    key = (bucket, request.remote_addr)
    now = time.time()
    window_start = now - window
    _hits[key] = [t for t in _hits.get(key, []) if t > window_start]
    if len(_hits[key]) >= limit:
        return False
    _hits[key].append(now)
    return True