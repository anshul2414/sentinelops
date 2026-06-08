"""Detection engine — correlation heuristics producing findings.
Each detector is gated by its rule's `enabled` flag."""
from collections import defaultdict

HOSTILE = ["RU", "CN", "KP", "NG"]


def _by(rows, keyfn):
    d = defaultdict(list)
    for r in rows:
        d[keyfn(r)].append(r)
    return d


def detect(events, enabled=None):
    """events: list of dicts (with _time, _raw, etc). enabled: set of detector keys."""
    if enabled is None:
        enabled = set(k for k in DETECTORS)
    findings = []

    def add(detector, **kw):
        kw["detector"] = detector
        kw["id"] = f"F-{len(findings)+1}"
        findings.append(kw)

    auth = [e for e in events if e.get("sourcetype") in ("linux_secure", "win_security")]
    fw = [e for e in events if e.get("sourcetype") == "firewall"]
    web = [e for e in events if e.get("sourcetype") == "apache_access"]
    edr = [e for e in events if e.get("sourcetype") == "endpoint_edr"]
    cloud = [e for e in events if e.get("sourcetype") == "cloudtrail"]
    ids = [e for e in events if e.get("sourcetype") == "ids_suricata"]

    # 1) brute force
    if "brute_force" in enabled:
        fails = _by([e for e in auth if e.get("action") == "failure"], lambda e: e.get("src_ip"))
        for ip, evs in fails.items():
            if len(evs) >= 15:
                success = next((e for e in auth if e.get("src_ip") == ip and e.get("action") == "success"), None)
                add("brute_force",
                    title="Successful brute-force compromise" if success else "Brute-force attack in progress",
                    severity="critical" if success else "high",
                    tactic="Credential Access", mitre="T1110 / T1078" if success else "T1110",
                    confidence=96 if success else 88, src_ip=ip, country=evs[0].get("country"),
                    evidence=f"{len(evs)} failed logins from {ip}" + (f', then SUCCESS for user "{success.get("user")}".' if success else "."),
                    recommendation=(f'Isolate affected host, force-reset "{success.get("user")}" credentials, review post-login activity for {ip}.'
                                    if success else f"Block {ip} at the firewall, enable rate-limiting / fail2ban, require MFA."),
                    count=len(evs))

    # 2) port scan
    if "port_scan" in enabled:
        for ip, evs in _by([e for e in fw if e.get("action") == "deny"], lambda e: e.get("src_ip")).items():
            ports = {e.get("dest_port") for e in evs}
            if len(ports) >= 20:
                add("port_scan", title="Network port scan detected", severity="medium",
                    tactic="Reconnaissance", mitre="T1046", confidence=90, src_ip=ip, country=evs[0].get("country"),
                    evidence=f"{ip} probed {len(ports)} distinct ports ({len(evs)} blocked connections).",
                    recommendation=f"Block {ip}, confirm exposed services are patched, add an IDS signature.", count=len(evs))

    # 3) web attack
    if "web_attack" in enabled:
        import re
        sig = re.compile(r"union select|or '1'='1|drop table|\.\./|/\.env|--|sqlmap", re.I)
        atk = [e for e in web if sig.search(e.get("_raw", "")) or "sqlmap" in str(e.get("user_agent", "")).lower()]
        for ip, evs in _by(atk, lambda e: e.get("src_ip")).items():
            if len(evs) >= 5:
                add("web_attack", title="Web application attack (SQLi / path traversal)", severity="high",
                    tactic="Initial Access", mitre="T1190", confidence=92, src_ip=ip, country=evs[0].get("country"),
                    evidence=f"{len(evs)} malicious requests from {ip} (tool: {evs[0].get('user_agent')}). Sample: {evs[0].get('uri')}",
                    recommendation=f"Enable WAF blocking for {ip}, patch injection points, audit DB access logs.", count=len(evs))

    # 4) credential dumping
    if "cred_dump" in enabled:
        import re
        for e in edr:
            if re.search(r"mimikatz|cobalt|psexec", str(e.get("process", "")) + str(e.get("_raw", "")), re.I):
                add("cred_dump", title="Credential-dumping / hacking tool executed", severity="critical",
                    tactic="Credential Access", mitre="T1003", confidence=98, src_ip=e.get("src_ip"), host=e.get("host"),
                    evidence=f'{e.get("process")} launched by "{e.get("user")}" on {e.get("host")}'
                             + (f' (parent: {e.get("parent")}).' if e.get("parent") else "."),
                    recommendation=f"Immediately isolate {e.get('host')}, capture memory, reset all credentials, hunt for lateral movement.", count=1)

    # 5) C2 beaconing
    if "c2_beacon" in enabled:
        beacons = _by([e for e in fw if e.get("action") == "allow" and e.get("country") in HOSTILE],
                      lambda e: f"{e.get('src_ip')}>{e.get('dest_ip')}")
        for k, evs in beacons.items():
            if len(evs) >= 8:
                s, d = k.split(">")
                add("c2_beacon", title="Command-and-control (C2) beaconing", severity="high",
                    tactic="Command and Control", mitre="T1071", confidence=85, src_ip=s, country=evs[0].get("country"),
                    evidence=f"{len(evs)} periodic outbound connections from {s} to {d}:{evs[0].get('dest_port')} ({evs[0].get('country')}).",
                    recommendation=f"Block {d}, isolate {s}, inspect host for implants / scheduled tasks.", count=len(evs))

    # 6) exfil
    if "exfil" in enabled:
        for ip, evs in _by([e for e in fw if e.get("action") == "allow" and (e.get("bytes") or 0) > 1_000_000],
                           lambda e: e.get("src_ip")).items():
            total = sum(e.get("bytes", 0) for e in evs)
            if total > 10_000_000:
                add("exfil", title="Possible data exfiltration", severity="high",
                    tactic="Exfiltration", mitre="T1041", confidence=82, src_ip=ip, country=evs[0].get("country"),
                    evidence=f"{total/1e6:.1f} MB transferred outbound from {ip} across {len(evs)} flows.",
                    recommendation=f"Throttle/block the destination, verify business justification, engage DLP review for {ip}.", count=len(evs))

    # 7) priv esc
    if "priv_esc" in enabled:
        for e in cloud:
            if "administratoraccess" in str(e.get("policy", "")).lower() or e.get("event_name") == "AttachUserPolicy":
                add("priv_esc", title="Privilege escalation in cloud IAM", severity="critical",
                    tactic="Privilege Escalation", mitre="T1098", confidence=90, src_ip=e.get("src_ip"), country=e.get("country"),
                    evidence=f'"{e.get("user")}" performed {e.get("event_name")}'
                             + (f' granting {e.get("policy")}' if e.get("policy") else "") + f' from {e.get("country")}.',
                    recommendation="Revoke the policy, disable the IAM principal, review CloudTrail for elevated actions.", count=1)

    # 8) impossible travel
    if "impossible_travel" in enabled:
        wins = [e for e in events if e.get("action") == "success" and e.get("country") and e.get("logon_type") == 10]
        for user, evs in _by(wins, lambda e: e.get("user")).items():
            evs.sort(key=lambda e: e.get("_time", 0))
            for i in range(1, len(evs)):
                fast = (evs[i]["_time"] - evs[i-1]["_time"]) < 20 * 60000
                hostile = evs[i].get("country") in HOSTILE or evs[i-1].get("country") in HOSTILE
                if evs[i].get("country") != evs[i-1].get("country") and fast and hostile:
                    add("impossible_travel", title="Impossible travel / anomalous login", severity="high",
                        tactic="Initial Access", mitre="T1078", confidence=80, host=evs[i].get("host"), src_ip=evs[i].get("src_ip"),
                        evidence=f'User "{user}" authenticated from {evs[i-1].get("country")} then {evs[i].get("country")} within {round((evs[i]["_time"]-evs[i-1]["_time"])/60000)} min.',
                        recommendation=f'Challenge "{user}" with MFA, invalidate sessions, confirm with the user.', count=2)
                    break

    # 9) IDS
    if "ids" in enabled and ids:
        for sig, evs in _by(ids, lambda e: e.get("signature")).items():
            add("ids", title="IDS signature: " + str(sig), severity="critical",
                tactic="Multiple", mitre="—", confidence=87, src_ip=evs[0].get("src_ip"), country=evs[0].get("country"),
                evidence=f'{len(evs)} alert(s) for "{sig}".',
                recommendation="Triage affected hosts, block the source, validate the signature is not a false positive.", count=len(evs))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), -f["confidence"]))
    for i, f in enumerate(findings):
        f["id"] = f"F-{i+1}"
    return findings


DETECTORS = ["brute_force", "port_scan", "web_attack", "cred_dump", "c2_beacon",
             "exfil", "priv_esc", "impossible_travel", "ids"]


def risk_score(findings):
    w = {"critical": 28, "high": 16, "medium": 7, "low": 2}
    s = sum(w.get(f["severity"], 0) * (f["confidence"] / 100) for f in findings)
    return min(100, round(s))
