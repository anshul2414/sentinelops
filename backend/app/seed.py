"""Telemetry generator — inserts realistic multi-source events plus seeded
attack scenarios so detections and the AI analyst have signal."""
import random
import time
from .models import Event, Rule

HOSTS = ["web-01", "web-02", "app-01", "app-02", "db-01", "auth-01", "fw-edge-01",
         "vpn-gw-01", "k8s-node-3", "win-dc-01", "win-fs-02", "mail-01"]
USERS = ["jsmith", "achen", "mrivera", "kpatel", "dlee", "svc_backup", "admin",
         "root", "tjones", "nwong", "ekim", "guest"]
INT_NETS = ["10.0.", "172.16.", "192.168."]
COUNTRIES = ["US", "DE", "GB", "IN", "BR", "NG", "RU", "CN", "KP", "NL", "FR", "SG"]
HOSTILE = ["RU", "CN", "KP", "NG"]
URLS = ["/login", "/api/v1/users", "/admin", "/api/v1/orders", "/static/app.js",
        "/wp-admin", "/.env", "/api/v1/auth/token", "/health", "/api/v1/export",
        "/phpmyadmin", "/api/v1/payments", "/api/v1/search"]
UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "curl/7.81.0",
      "python-requests/2.31", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)",
      "Go-http-client/2.0"]
BENIGN_PROCS = ["svchost.exe", "explorer.exe", "ssh", "bash", "python3", "wget", "curl"]

ri = lambda a, b: random.randint(a, b)
rc = random.choice


def ext_ip():
    return f"{ri(11,223)}.{ri(0,255)}.{ri(0,255)}.{ri(1,254)}"


def int_ip():
    return f"{rc(INT_NETS)}{ri(0,40)}.{ri(2,254)}"


def ev(ts, sourcetype, host, severity, raw, **fields):
    return Event(ts=ts, sourcetype=sourcetype, host=host, severity=severity, raw=raw, **fields)


def generate(count=2400):
    now = int(time.time() * 1000)
    span = 24 * 3600 * 1000
    out = []

    def rt():
        return now - random.randint(0, span)

    for _ in range(count):
        pick = random.random()
        t = rt()
        if pick < 0.20:   # firewall
            action = "allow" if random.random() < 0.78 else "deny"
            src = int_ip() if random.random() < 0.5 else ext_ip()
            dst = int_ip(); port = rc([22, 80, 443, 443, 3389, 53, 8080, 25, 3306])
            out.append(ev(t, "firewall", "fw-edge-01", "low" if action == "deny" else "info",
                          f"action={action} src={src} dst={dst}:{port}",
                          action=action, src_ip=src, dest_ip=dst, dest_port=port,
                          protocol=rc(["TCP", "UDP"]), bytes=ri(80, 4000), country=rc(COUNTRIES)))
        elif pick < 0.42:  # web
            code = rc([200, 200, 200, 301, 404, 500, 403, 200]); ip = ext_ip() if random.random() < 0.6 else int_ip()
            url = rc(URLS)
            out.append(ev(t, "apache_access", rc(["web-01", "web-02"]), "low" if code >= 500 else "info",
                          f'{ip} "{url}" {code}', src_ip=ip, status=code, uri=url,
                          method=rc(["GET", "POST", "GET", "GET"]), bytes=ri(120, 9000),
                          user_agent=rc(UA), country=rc(COUNTRIES)))
        elif pick < 0.60:  # linux auth
            ok = random.random() < 0.82; user = rc(USERS); ip = int_ip() if random.random() < 0.5 else ext_ip()
            out.append(ev(t, "linux_secure", rc(["app-01", "auth-01", "db-01"]), "info" if ok else "low",
                          f"sshd: {'Accepted' if ok else 'Failed'} password for {user} from {ip}",
                          action="success" if ok else "failure", user=user, src_ip=ip,
                          service="sshd", country=rc(COUNTRIES)))
        elif pick < 0.72:  # windows auth
            ok = random.random() < 0.85; user = rc(USERS)
            out.append(ev(t, "win_security", rc(["win-dc-01", "win-fs-02"]), "info" if ok else "low",
                          f"EventID={4624 if ok else 4625} user={user} logon",
                          action="success" if ok else "failure", user=user, src_ip=int_ip(),
                          event_id=4624 if ok else 4625, logon_type=rc([2, 3, 10])))
        elif pick < 0.82:  # edr
            proc = rc(BENIGN_PROCS)
            out.append(ev(t, "endpoint_edr", rc(["win-fs-02", "app-02", "k8s-node-3"]), "info",
                          f"process_start {proc}", process=proc, user=rc(USERS),
                          action="process_start", src_ip=int_ip()))
        elif pick < 0.92:  # dns
            dom = rc(["update.microsoft.com", "api.github.com", "cdn.jsdelivr.net",
                      "pool.ntp.org", "slack.com", "google.com", "internal.corp"])
            out.append(ev(t, "dns", "win-dc-01", "info", f"dns query {dom}",
                          query=dom, src_ip=int_ip(), record="A"))
        else:              # cloudtrail
            evn = rc(["GetObject", "PutObject", "AssumeRole", "DescribeInstances", "CreateUser", "ConsoleLogin"])
            out.append(ev(t, "cloudtrail", "aws", "info", f"cloudtrail {evn}",
                          event_name=evn, user=rc(USERS), src_ip=ext_ip(),
                          action="success" if random.random() < 0.95 else "failure", country=rc(COUNTRIES)))

    # ---------------- Seeded attack scenarios ----------------
    bf_ip = f"45.131.{ri(10,99)}.{ri(2,254)}"
    bf0 = now - 3 * 3600 * 1000
    for i in range(64):
        out.append(ev(bf0 + i * 9000, "linux_secure", "auth-01", "medium",
                      f"sshd: Failed password for {rc(['root','admin'])} from {bf_ip}",
                      action="failure", user=rc(["root", "admin", "test", "oracle", "postgres"]),
                      src_ip=bf_ip, service="sshd", country="RU"))
    out.append(ev(bf0 + 64 * 9000, "linux_secure", "auth-01", "high",
                  f"sshd: Accepted password for root from {bf_ip}",
                  action="success", user="root", src_ip=bf_ip, service="sshd", country="RU"))

    scan_ip = f"185.220.{ri(10,99)}.{ri(2,254)}"; s0 = now - 90 * 60 * 1000
    for i in range(48):
        out.append(ev(s0 + i * 2000, "firewall", "fw-edge-01", "medium",
                      f"action=deny src={scan_ip} dst=10.0.1.10:{ri(1,9000)}",
                      action="deny", src_ip=scan_ip, dest_ip="10.0.1.10",
                      dest_port=ri(1, 9000), protocol="TCP", bytes=ri(40, 90), country="NL"))

    atk_ip = f"103.97.{ri(10,99)}.{ri(2,254)}"; a0 = now - 50 * 60 * 1000
    payloads = ["/api/v1/users?id=1' OR '1'='1", "/api/v1/search?q=' UNION SELECT",
                "/../../etc/passwd", "/.env", "/admin' --", "/api/v1/orders?id=1;DROP TABLE"]
    for i in range(30):
        pl = rc(payloads)
        out.append(ev(a0 + i * 11000, "apache_access", "web-01", "high",
                      f"{atk_ip} sqlmap {pl}", src_ip=atk_ip, status=rc([403, 500, 200, 404]),
                      uri=pl, method="GET", bytes=ri(200, 1200), user_agent="sqlmap/1.7", country="CN"))

    c2_ip = f"194.5.{ri(10,99)}.{ri(2,254)}"; m0 = now - 38 * 60 * 1000
    out.append(ev(m0, "endpoint_edr", "win-fs-02", "critical",
                  "EDR ALERT: credential dumping tool mimikatz.exe executed by tjones",
                  process="mimikatz.exe", user="tjones", action="process_start",
                  src_ip="10.0.5.22", parent="powershell.exe"))
    for i in range(18):
        out.append(ev(m0 + 60000 + i * 60000, "firewall", "fw-edge-01", "high",
                      f"beacon src=10.0.5.22 dst={c2_ip}:443",
                      action="allow", src_ip="10.0.5.22", dest_ip=c2_ip, dest_port=443,
                      protocol="TCP", bytes=ri(900, 1500), country="KP"))

    e0 = now - 25 * 60 * 1000
    for i in range(12):
        out.append(ev(e0 + i * 45000, "firewall", "fw-edge-01", "high",
                      f"large transfer src=db-01 {ri(4,9)}MB outbound",
                      action="allow", src_ip="10.0.3.50", dest_ip=ext_ip(), dest_port=8443,
                      protocol="TCP", bytes=ri(4_000_000, 9_000_000), country="NG"))

    cl0 = now - 70 * 60 * 1000
    out.append(ev(cl0, "cloudtrail", "aws", "high", "cloudtrail CreateUser by svc_backup",
                  event_name="CreateUser", user="svc_backup", src_ip=ext_ip(), action="success", country="RU"))
    out.append(ev(cl0 + 30000, "cloudtrail", "aws", "critical", "svc_backup attached AdministratorAccess",
                  event_name="AttachUserPolicy", user="svc_backup", src_ip=ext_ip(),
                  action="success", country="RU", policy="AdministratorAccess"))

    it0 = now - 20 * 60 * 1000
    out.append(ev(it0, "win_security", "win-dc-01", "low", "EventID=4624 user=achen from US",
                  action="success", user="achen", src_ip=ext_ip(), event_id=4624, country="US", logon_type=10))
    out.append(ev(it0 + 4 * 60 * 1000, "win_security", "win-dc-01", "high", "EventID=4624 user=achen from CN",
                  action="success", user="achen", src_ip=ext_ip(), event_id=4624, country="CN", logon_type=10))

    for _ in range(6):
        out.append(ev(now - ri(5, 120) * 60000, "ids_suricata", "fw-edge-01", "critical",
                      "IDS signature triggered",
                      signature=rc(["ET MALWARE Cobalt Strike Beacon", "ET EXPLOIT Log4j RCE Attempt",
                                     "ET SCAN Nmap", "ET TROJAN Generic C2 CheckIn"]),
                      src_ip=ext_ip(), dest_ip=int_ip(), country=rc(HOSTILE), action="alert"))

    out.sort(key=lambda e: e.ts)
    return out


DEFAULT_RULES = [
    ("SSH Brute Force", "≥15 auth failures from one source in 1h", "high", "🔑", "brute_force"),
    ("Port Scan Detection", "≥20 distinct dest ports denied from one src", "medium", "📡", "port_scan"),
    ("Web App Attack (SQLi/Traversal)", "sqlmap signatures & injection payloads", "high", "🌐", "web_attack"),
    ("Credential Dumping", "mimikatz / cobalt strike on endpoint", "critical", "🧬", "cred_dump"),
    ("C2 Beaconing", "Periodic outbound to high-risk geo", "high", "📶", "c2_beacon"),
    ("Data Exfiltration", ">10MB outbound to external host", "high", "📤", "exfil"),
    ("Cloud Privilege Escalation", "AdministratorAccess policy attach", "critical", "☁️", "priv_esc"),
    ("Impossible Travel", "Same user, 2 geos within 20m (remote logon)", "high", "✈️", "impossible_travel"),
    ("IDS Signature Alerts", "Suricata/ET critical signatures", "critical", "🚨", "ids"),
]


def seed_rules():
    return [Rule(name=n, description=d, severity=s, icon=i, detector=k, enabled=True)
            for (n, d, s, i, k) in DEFAULT_RULES]
