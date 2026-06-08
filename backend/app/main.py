"""SentinelOps SIEM — FastAPI app (auth + REST API + MCP + static frontend)."""
import os
import time
from fastapi import FastAPI, Depends, HTTPException, Request, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import Base, engine, get_db, SessionLocal
from . import models, search as spl, detect as det, ai as analyst, security as sec
from .auth import router as auth_router, _client_ip
from .seed import generate, seed_rules

RANGES = {"15m": 9e5, "1h": 36e5, "4h": 144e5, "24h": 864e5, "all": 9e15}
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")

_PROD = os.getenv("ENV", "dev").lower() in ("prod", "production")
app = FastAPI(title="SentinelOps SIEM API", version="2.5.0",
              docs_url=None if _PROD else "/docs",
              redoc_url=None if _PROD else "/redoc",
              openapi_url=None if _PROD else "/openapi.json")


# ---------------- security headers + CSRF cookie ----------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    csp = ("default-src 'self'; "
           "script-src 'self' https://cdn.jsdelivr.net; "
           "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
           "font-src 'self' https://fonts.gstatic.com; "
           "img-src 'self' data:; connect-src 'self'; "
           "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
    resp.headers["Content-Security-Policy"] = csp
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if sec.cookie_secure_flag():
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# ---------------- startup ----------------
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(models.Event).count() == 0:
            db.bulk_save_objects(generate(2400))
            db.add_all(seed_rules())
            db.commit()
        if db.query(models.Finding).count() == 0:
            _recompute_findings(db)
        # optional seeded admin (only if creds provided via env — never a default password)
        admin_user = os.getenv("ADMIN_USERNAME")
        admin_pass = os.getenv("ADMIN_PASSWORD")
        if admin_user and admin_pass and not db.query(models.User).filter(models.User.username == admin_user).first():
            db.add(models.User(username=admin_user, email=os.getenv("ADMIN_EMAIL", f"{admin_user}@local"),
                               password_hash=sec.hash_password(admin_pass), role="admin",
                               api_token=sec.new_api_token(), active=True))
            db.commit()
    finally:
        db.close()


def _events_in_range(db, rng="24h"):
    cut = int(time.time() * 1000) - RANGES.get(rng, 864e5)
    rows = db.query(models.Event).filter(models.Event.ts >= cut).order_by(models.Event.ts).all()
    return [e.to_dict() for e in rows]


def _enabled_detectors(db):
    return {r.detector for r in db.query(models.Rule).all() if r.enabled}


def _recompute_findings(db):
    events = _events_in_range(db, "24h")
    enabled = _enabled_detectors(db) or set(det.DETECTORS)
    findings = det.detect(events, enabled)
    db.query(models.Finding).delete()
    for f in findings:
        db.add(models.Finding(
            fid=f["id"], title=f["title"], severity=f["severity"], tactic=f["tactic"],
            mitre=f["mitre"], confidence=f["confidence"], src_ip=f.get("src_ip"),
            country=f.get("country"), host=f.get("host"), evidence=f["evidence"],
            recommendation=f["recommendation"], count=f["count"], detector=f["detector"]))
    db.commit()
    return findings


# ---------------- schemas ----------------
class SearchReq(BaseModel):
    query: str = "*"
    range: str = "24h"


class ChatReq(BaseModel):
    message: str
    range: str = "24h"


class IngestReq(BaseModel):
    sourcetype: str
    host: str = "external"
    severity: str = "info"
    raw: str = ""
    fields: dict = {}


class IncidentReq(BaseModel):
    finding_id: str


class McpCall(BaseModel):
    tool: str
    arguments: dict = {}


# ================= auth pages =================
app.include_router(auth_router)


# ================= API (auth required) =================
api = APIRouter(prefix="/api", dependencies=[Depends(sec.get_current_user)])
analyst_role = Depends(sec.require_role("analyst"))
admin_role = Depends(sec.require_role("admin"))


@api.get("/health")
def health(db: Session = Depends(get_db)):
    return {"status": "ok", "events": db.query(models.Event).count(),
            "findings": db.query(models.Finding).count(), "version": "2.5.0"}


@api.get("/me")
def me(user: models.User = Depends(sec.get_current_user)):
    return {"username": user.username, "role": user.role, "email": user.email}


@api.get("/stats/overview")
def overview(range: str = "24h", db: Session = Depends(get_db)):
    events = _events_in_range(db, range)
    findings = [f.to_dict() for f in db.query(models.Finding).all()]
    src, geo, talkers, blocked = {}, {}, {}, 0
    for e in events:
        if e.get("action") in ("deny", "failure"):
            blocked += 1
        src[e["sourcetype"]] = src.get(e["sourcetype"], 0) + 1
        if e.get("country"):
            geo[e["country"]] = geo.get(e["country"], 0) + 1
        if e.get("src_ip"):
            talkers[e["src_ip"]] = talkers.get(e["src_ip"], 0) + 1
    span = 3600000
    buckets = {}
    for e in events:
        b = (e["_time"] // span) * span
        buckets.setdefault(b, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        buckets[b][e["severity"]] = buckets[b].get(e["severity"], 0) + 1
    timeline = [{"t": t, **buckets[t]} for t in sorted(buckets)]
    top = lambda d, n=7: sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return {"total_events": len(events), "findings": len(findings),
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high": len([f for f in findings if f["severity"] == "high"]),
            "blocked": blocked, "risk_score": det.risk_score(findings),
            "by_source": dict(top(src, 8)), "by_country": top(geo), "top_talkers": top(talkers),
            "timeline": timeline,
            "sources_health": [{"sourcetype": s, "count": src.get(s, 0)} for s in
                               ["firewall", "linux_secure", "win_security", "apache_access",
                                "ids_suricata", "cloudtrail", "endpoint_edr", "dns"]]}


@api.post("/search")
def do_search(req: SearchReq, db: Session = Depends(get_db)):
    events = _events_in_range(db, req.range)
    try:
        res = spl.run(events, req.query or "*")
    except Exception as e:
        raise HTTPException(400, f"Query error: {e}")
    if res["type"] == "events":
        res["rows"] = sorted(res["rows"], key=lambda r: r.get("_time", 0), reverse=True)[:300]
    return {"type": res["type"], "count": len(res["rows"]),
            "columns": res.get("columns"), "rows": res["rows"], "span": res.get("span")}


@api.get("/findings")
def get_findings(severity: str = None, db: Session = Depends(get_db)):
    q = db.query(models.Finding)
    if severity:
        q = q.filter(models.Finding.severity == severity)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items = sorted([f.to_dict() for f in q.all()], key=lambda f: (order.get(f["severity"], 9), -f["confidence"]))
    return {"findings": items, "risk_score": det.risk_score(items)}


@api.post("/analyze")
def analyze(request: Request, db: Session = Depends(get_db), user: models.User = analyst_role):
    findings = _recompute_findings(db)
    sec.audit(db, user.username, "analyze", f"{len(findings)} findings", _client_ip(request))
    return {"findings": len(findings), "risk_score": det.risk_score(findings)}


@api.get("/rules")
def get_rules(db: Session = Depends(get_db)):
    return {"rules": [{"id": r.id, "name": r.name, "description": r.description, "severity": r.severity,
                       "enabled": r.enabled, "icon": r.icon, "detector": r.detector}
                      for r in db.query(models.Rule).all()]}


@api.patch("/rules/{rule_id}")
def toggle_rule(rule_id: int, request: Request, db: Session = Depends(get_db), user: models.User = analyst_role):
    r = db.query(models.Rule).get(rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    r.enabled = not r.enabled
    db.commit()
    _recompute_findings(db)
    sec.audit(db, user.username, "toggle_rule", f"{r.name}={r.enabled}", _client_ip(request))
    return {"id": r.id, "enabled": r.enabled}


@api.get("/sources")
def sources(range: str = "24h", db: Session = Depends(get_db)):
    events = _events_in_range(db, range)
    cat = {"firewall": "Network", "linux_secure": "Auth", "win_security": "Auth", "apache_access": "Web",
           "ids_suricata": "IDS/IPS", "cloudtrail": "Cloud", "endpoint_edr": "Endpoint", "dns": "Network"}
    out = []
    for s in ["firewall", "linux_secure", "win_security", "apache_access",
              "ids_suricata", "cloudtrail", "endpoint_edr", "dns"]:
        evs = [e for e in events if e["sourcetype"] == s]
        out.append({"sourcetype": s, "category": cat.get(s, "—"), "count": len(evs),
                    "last_event": max((e["_time"] for e in evs), default=0),
                    "status": "healthy" if evs else "offline"})
    return {"sources": out}


@api.post("/ingest")
def ingest(req: IngestReq, request: Request, db: Session = Depends(get_db), user: models.User = analyst_role):
    e = models.Event(ts=int(time.time() * 1000), sourcetype=req.sourcetype, host=req.host,
                     severity=req.severity, raw=req.raw)
    for k, v in (req.fields or {}).items():
        if hasattr(e, k) and k not in ("id",):
            setattr(e, k, v)
    db.add(e)
    db.commit()
    sec.audit(db, user.username, "ingest", req.sourcetype, _client_ip(request))
    return {"id": e.id, "status": "ingested"}


@api.get("/stream/recent")
def recent(limit: int = 30, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 100))
    rows = db.query(models.Event).order_by(models.Event.ts.desc()).limit(limit).all()
    return {"events": [e.to_dict() for e in rows]}


@api.get("/incidents")
def incidents(db: Session = Depends(get_db)):
    return {"incidents": [i.to_dict() for i in db.query(models.Incident).order_by(models.Incident.id.desc()).all()]}


@api.post("/incidents")
def create_incident(req: IncidentReq, request: Request, db: Session = Depends(get_db), user: models.User = analyst_role):
    f = db.query(models.Finding).filter(models.Finding.fid == req.finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    inc = models.Incident(finding_id=f.fid, title=f.title, severity=f.severity)
    db.add(inc)
    db.commit()
    sec.audit(db, user.username, "create_incident", f.title, _client_ip(request))
    return inc.to_dict()


@api.post("/ai/chat")
def ai_chat(req: ChatReq, db: Session = Depends(get_db)):
    events = _events_in_range(db, req.range)
    findings = [f.to_dict() for f in db.query(models.Finding).all()]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), -f["confidence"]))
    return {"answer": analyst.ask(req.message, events, findings)}


@api.get("/users")
def list_users(db: Session = Depends(get_db), user: models.User = admin_role):
    return {"users": [u.to_dict() for u in db.query(models.User).order_by(models.User.id).all()]}


@api.get("/audit")
def audit_log(limit: int = 50, db: Session = Depends(get_db), user: models.User = admin_role):
    limit = max(1, min(limit, 200))
    rows = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(limit).all()
    return {"audit": [a.to_dict() for a in rows]}


app.include_router(api)


# ================= MCP (auth required) =================
mcp = APIRouter(prefix="/mcp", dependencies=[Depends(sec.get_current_user)])
MCP_TOOLS = [
    {"name": "siem.search", "description": "Run an SPL query and return matching events",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "range": {"type": "string"}}, "required": ["query"]}},
    {"name": "siem.get_findings", "description": "List AI-correlated findings with severity & MITRE mapping",
     "inputSchema": {"type": "object", "properties": {"severity": {"type": "string"}}}},
    {"name": "siem.analyze", "description": "Re-run the detection engine over the window",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "siem.overview", "description": "Get dashboard KPIs and risk score",
     "inputSchema": {"type": "object", "properties": {"range": {"type": "string"}}}},
    {"name": "siem.create_incident", "description": "Open an incident from a finding (analyst role)",
     "inputSchema": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
]


@mcp.get("/tools")
def mcp_tools():
    return {"tools": MCP_TOOLS}


@mcp.post("/call")
def mcp_call(call: McpCall, request: Request, db: Session = Depends(get_db),
             user: models.User = Depends(sec.get_current_user)):
    t, a = call.tool, call.arguments or {}
    if t == "siem.search":
        return do_search(SearchReq(query=a.get("query", "*"), range=a.get("range", "24h")), db)
    if t == "siem.get_findings":
        return get_findings(a.get("severity"), db)
    if t == "siem.overview":
        return overview(a.get("range", "24h"), db)
    if t in ("siem.analyze", "siem.create_incident"):
        if sec.ROLE_RANK.get(user.role, -1) < sec.ROLE_RANK["analyst"]:
            raise HTTPException(403, "Requires 'analyst' role or higher")
        if t == "siem.analyze":
            return analyze(request, db, user)
        return create_incident(IncidentReq(finding_id=a["finding_id"]), request, db, user)
    raise HTTPException(400, f"Unknown tool: {t}")


app.include_router(mcp)


# ================= guarded frontend =================
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def root(request: Request, db: Session = Depends(get_db)):
        if not sec._principal(request, db)[0]:
            return RedirectResponse("/login", status_code=302)
        resp = FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
        sec.ensure_csrf(request, resp)   # make sure SPA has a CSRF cookie for POSTs
        return resp
