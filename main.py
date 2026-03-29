"""
CyberShield — FastAPI Backend
Endpoints:
  GET  /                       → serves index.html UI
  POST /analyze-url            → phishing threat analysis
  GET  /pwned-check/{prefix}   → HIBP k-anonymity proxy
  POST /scan-headers           → HTTP security headers scanner
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse
import httpx
import re
import os
import ssl
import socket

# ═══════════════════════════════
# APP SETUP
# ═══════════════════════════════
app = FastAPI(title="CyberShield API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_PATH = os.path.join(os.path.dirname(__file__), "index.html")


# ═══════════════════════════════
# SCHEMAS — MODULE 1 (URL ANALYZER)
# ═══════════════════════════════
class URLRequest(BaseModel):
    url: str

class Features(BaseModel):
    url_length: int
    has_at_symbol: bool
    hyphen_count: int
    dot_count: int
    digit_count: int
    missing_https: bool
    phish_keywords: bool
    has_ip_address: bool
    subdomain_count: int
    suspicious_tld: bool

class UrlComponents(BaseModel):
    scheme: str
    domain: str
    path: str
    query: str

class ThreatResponse(BaseModel):
    threat_score: int
    verdict: str
    color: str
    features: Features
    components: UrlComponents


# ═══════════════════════════════
# SCHEMAS — MODULE 2 (PWNED)
# ═══════════════════════════════
class PwnedResponse(BaseModel):
    hashes: str


# ═══════════════════════════════
# SCHEMAS — MODULE 3 (HEADERS)
# ═══════════════════════════════
class HeaderScanRequest(BaseModel):
    url: str

class HeaderDetail(BaseModel):
    name: str
    present: bool
    value: Optional[str] = None
    description: str
    severity: str   # "critical" | "high" | "medium" | "low"
    fix_suggestion: Optional[str] = None

class HeaderScanResponse(BaseModel):
    grade: str
    score: int
    headers: list[HeaderDetail]
    server_info: Optional[str] = None
    redirect_chain: list[str]
    final_url: str
    tls_version: Optional[str] = None


# ═══════════════════════════════
# PHISHING KEYWORDS
# ═══════════════════════════════
PHISH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "secure", "security", "update", "confirm",
    "banking", "paypal", "ebay", "amazon", "apple", "google",
    "microsoft", "netflix", "password", "credential", "wallet",
    "crypto", "bitcoin", "free", "winner", "prize", "click",
    "urgent", "suspended", "limited", "unusual", "activity",
    "webscr", "cmd=", "dispatch", "token", "auth", "oauth",
    "verify-account", "recover", "unlock", "reactivate", "restore",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".club",
    ".top", ".work", ".click", ".loan", ".download", ".zip",
    ".review", ".country", ".kim", ".science", ".stream",
}


# ═══════════════════════════════
# URL FEATURE EXTRACTOR
# ═══════════════════════════════
def extract_features(url: str) -> dict:
    url_lower = url.lower()

    # Check for IP address in host
    host_match = re.search(r"://([^/]+)", url)
    host = host_match.group(1) if host_match else ""
    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", host))

    # Subdomain count
    clean_host = host.split(":")[0]
    parts = clean_host.split(".")
    subdomain_count = max(0, len(parts) - 2)

    # Suspicious TLD
    tld = "." + parts[-1] if parts else ""
    is_suspicious_tld = tld.lower() in SUSPICIOUS_TLDS

    has_phish = any(kw in url_lower for kw in PHISH_KEYWORDS)

    return {
        "url_length":      len(url),
        "has_at_symbol":   "@" in url,
        "hyphen_count":    url.count("-"),
        "dot_count":       url.count("."),
        "digit_count":     sum(c.isdigit() for c in url),
        "missing_https":   not url_lower.startswith("https://"),
        "phish_keywords":  has_phish,
        "has_ip_address":  has_ip,
        "subdomain_count": subdomain_count,
        "suspicious_tld":  is_suspicious_tld,
    }


# ═══════════════════════════════
# THREAT SCORE CALCULATOR
# ═══════════════════════════════
def calculate_threat_score(f: dict) -> int:
    score = 0
    ln = f["url_length"]
    if ln > 120: score += 15
    elif ln > 80: score += 10
    elif ln > 54: score += 5
    if f["has_at_symbol"]: score += 18
    h = f["hyphen_count"]
    if h >= 5: score += 12
    elif h >= 3: score += 7
    elif h >= 1: score += 2
    d = f["dot_count"]
    if d >= 6: score += 8
    elif d >= 4: score += 4
    dg = f["digit_count"]
    if dg >= 8: score += 7
    elif dg >= 4: score += 3
    if f["missing_https"]: score += 15
    if f["phish_keywords"]: score += 20
    if f["has_ip_address"]: score += 15
    sc = f["subdomain_count"]
    if sc >= 4: score += 8
    elif sc >= 2: score += 4
    if f["suspicious_tld"]: score += 10
    return min(score, 100)


# ═══════════════════════════════
# /analyze-url ENDPOINT
# ═══════════════════════════════
@app.post("/analyze-url", response_model=ThreatResponse)
async def analyze_url(request: URLRequest):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
        
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    features = extract_features(url)
    threat_score = calculate_threat_score(features)

    if threat_score <= 30:
        verdict, color = "SAFE", "green"
    elif threat_score <= 60:
        verdict, color = "SUSPICIOUS", "orange"
    else:
        verdict, color = "LIKELY PHISHING", "red"
        
    parsed = urlparse(url)
    components = UrlComponents(
        scheme=parsed.scheme,
        domain=parsed.netloc,
        path=parsed.path if parsed.path else "/",
        query=parsed.query
    )

    return ThreatResponse(
        threat_score=threat_score,
        verdict=verdict,
        color=color,
        features=Features(**features),
        components=components
    )


# ═══════════════════════════════
# /pwned-check/{prefix} ENDPOINT
# ═══════════════════════════════
@app.get("/pwned-check/{prefix}", response_model=PwnedResponse)
async def pwned_check(prefix: str):
    if len(prefix) != 5 or not re.fullmatch(r"[0-9A-Fa-f]{5}", prefix):
        raise HTTPException(status_code=400, detail="Prefix must be exactly 5 hex characters")

    hibp_url = f"https://api.pwnedpasswords.com/range/{prefix.upper()}"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                hibp_url,
                headers={"User-Agent": "CyberShield/3.0", "Add-Padding": "true"},
            )
            resp.raise_for_status()
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Breach database temporarily unavailable — try again shortly",
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")

    return PwnedResponse(hashes=resp.text)


# ═══════════════════════════════
# /scan-headers ENDPOINT
# ═══════════════════════════════
SECURITY_HEADERS = [
    {
        "key":         "strict-transport-security",
        "name":        "Strict-Transport-Security",
        "description": "Enforces HTTPS connections to the server (HSTS)",
        "severity":    "critical",
        "fix":         "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
    },
    {
        "key":         "content-security-policy",
        "name":        "Content-Security-Policy",
        "description": "Prevents XSS attacks by controlling which resources can load",
        "severity":    "critical",
        "fix":         "Implement a strict CSP restricting script sources, e.g., 'default-src \'self\''.",
    },
    {
        "key":         "x-frame-options",
        "name":        "X-Frame-Options",
        "description": "Prevents clickjacking via iframe embedding",
        "severity":    "high",
        "fix":         "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
    },
    {
        "key":         "x-content-type-options",
        "name":        "X-Content-Type-Options",
        "description": "Blocks MIME-type sniffing attacks",
        "severity":    "high",
        "fix":         "Add 'X-Content-Type-Options: nosniff'.",
    },
    {
        "key":         "referrer-policy",
        "name":        "Referrer-Policy",
        "description": "Controls how much referrer information is sent",
        "severity":    "medium",
        "fix":         "Set to 'strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    {
        "key":         "permissions-policy",
        "name":        "Permissions-Policy",
        "description": "Restricts access to browser APIs (camera, mic, etc.)",
        "severity":    "medium",
        "fix":         "Explicitly disable unused APIs, e.g., 'camera=(), microphone=()'.",
    },
    {
        "key":         "cross-origin-opener-policy",
        "name":        "Cross-Origin-Opener-Policy",
        "description": "Isolates browsing context to prevent cross-origin attacks",
        "severity":    "medium",
        "fix":         "Set to 'same-origin'.",
    },
    {
        "key":         "x-xss-protection",
        "name":        "X-XSS-Protection",
        "description": "Legacy XSS filter for older browsers",
        "severity":    "low",
        "fix":         "Add 'X-XSS-Protection: 1; mode=block'. Note: CSP is preferred.",
    },
]

SEVERITY_WEIGHTS = {"critical": 25, "high": 20, "medium": 12, "low": 8}


def compute_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 75: return "A"
    if score >= 60: return "B"
    if score >= 45: return "C"
    if score >= 25: return "D"
    return "F"


@app.post("/scan-headers", response_model=HeaderScanResponse)
async def scan_headers(request: HeaderScanRequest):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    redirect_chain: list[str] = []
    final_url = url

    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "CyberShield-SecurityScanner/3.0"},
        ) as client:
            resp = await client.get(url)
            for h in resp.history:
                redirect_chain.append(str(h.url))
            final_url = str(resp.url)
            response_headers = dict(resp.headers)

    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Target host timed out — try again shortly")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach target: {str(e)}")

    header_results: list[HeaderDetail] = []
    total_possible = sum(SEVERITY_WEIGHTS[h["severity"]] for h in SECURITY_HEADERS)
    earned = 0

    for hdef in SECURITY_HEADERS:
        val = response_headers.get(hdef["key"])
        present = val is not None
        if present:
            earned += SEVERITY_WEIGHTS[hdef["severity"]]
        header_results.append(
            HeaderDetail(
                name=hdef["name"],
                present=present,
                value=val[:120] if val else None,
                description=hdef["description"],
                severity=hdef["severity"],
                fix_suggestion=hdef["fix"] if not present else None
            )
        )

    score = round((earned / total_possible) * 100)
    grade = compute_grade(score)

    server_info = response_headers.get("server") or response_headers.get("x-powered-by")

    tls_ver = None
    try:
        host_part = re.sub(r"https?://([^/:]+).*", r"\1", final_url)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host_part) as s:
            s.settimeout(4)
            s.connect((host_part, 443))
            tls_ver = s.version()
    except Exception:
        pass

    return HeaderScanResponse(
        grade=grade,
        score=score,
        headers=header_results,
        server_info=server_info,
        redirect_chain=redirect_chain,
        final_url=final_url,
        tls_version=tls_ver,
    )


# ═══════════════════════════════
# ROOT — SERVE FRONTEND UI
# ═══════════════════════════════
@app.get("/")
async def root():
    if os.path.exists(FRONTEND_PATH):
        return FileResponse(FRONTEND_PATH, media_type="text/html")
    return {"status": "online", "service": "CyberShield API v3.0"}


@app.get("/health")
async def health():
    return {"status": "online", "service": "CyberShield API v3.0"}
