"""AI Security Analyst — natural-language assistant over the live dataset.
Intent-routed, deterministic and explainable (no external API required).
If OPENAI_API_KEY is set, falls back to an LLM for free-form questions."""
import os
import re
from .detect import risk_score, HOSTILE


def _ul(items):
    return "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"


def ask(question, events, findings):
    q = question.lower()

    if re.search(r"summary|overview|what.*(happen|going on)|brief|posture|status|threat", q):
        crit = [f for f in findings if f["severity"] == "critical"]
        high = [f for f in findings if f["severity"] == "high"]
        score = risk_score(findings)
        lvl = "CRITICAL" if score >= 70 else "ELEVATED" if score >= 40 else "GUARDED" if score >= 15 else "LOW"
        sources = len({e.get("sourcetype") for e in events})
        out = f"<h4>🛡️ Security Posture: {lvl} (risk {score}/100)</h4>"
        out += f"<p>Analyzed <b>{len(events):,}</b> events across {sources} data sources. "
        out += f"Detected <b>{len(findings)}</b> findings — <b>{len(crit)} critical</b>, <b>{len(high)} high</b>.</p>"
        if findings:
            out += "<b>Top priorities:</b>" + _ul([
                f'<span class="tag {f["severity"]}">{f["severity"]}</span> {f["title"]} — '
                f'<code>{f.get("src_ip") or f.get("host") or "—"}</code> ({f["confidence"]}% conf, {f["mitre"]})'
                for f in findings[:5]])
        out += '<p class="muted">Ask me: "show brute force", "what should I do about the malware", "top source IPs", or "events from RU".</p>'
        return out

    if re.search(r"recommend|what should|how do i|remediat|respond|mitigat|fix|action", q):
        if not findings:
            return "<p>No active threats detected — maintain monitoring. ✅</p>"
        return "<h4>Recommended response actions</h4>" + _ul(
            [f'<b>{f["title"]}:</b> {f["recommendation"]}' for f in findings[:6]])

    intent_map = [
        (r"brute|password|login fail|credential", r"brute|compromise"),
        (r"port scan|scan|recon", r"scan"),
        (r"sql|web attack|injection|sqlmap", r"web application"),
        (r"malware|mimikatz|c2|beacon|virus|trojan", r"credential-dump|beacon|IDS"),
        (r"exfil|data loss|leak", r"exfiltration"),
        (r"privilege|escalat|iam|admin access", r"privilege"),
        (r"impossible travel|anomal.*login|geo", r"impossible travel"),
    ]
    for qre, fre in intent_map:
        if re.search(qre, q):
            hits = [f for f in findings if re.search(fre, f["title"], re.I)]
            if not hits:
                return "<p>No findings of that type in the current window. 👍</p>"
            return _ul([
                f'<span class="tag {f["severity"]}">{f["severity"]}</span> <b>{f["title"]}</b><br>'
                f'{f["evidence"]}<br>➡️ <i>{f["recommendation"]}</i> <span class="mitre">{f["mitre"]}</span>'
                for f in hits])

    if re.search(r"top.*(ip|source|talker|attacker)|who.*attack|busiest", q):
        counts = {}
        for e in events:
            ip = e.get("src_ip")
            if ip:
                counts[ip] = counts.get(ip, 0) + 1
        top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        return "<h4>Top source IPs by event volume</h4>" + _ul([f"<code>{ip}</code> — {c} events" for ip, c in top])

    cm = re.search(r"from ([a-z]{2})\b|country\s*=?\s*([a-z]{2})", q)
    if cm:
        cc = (cm.group(1) or cm.group(2)).upper()
        evs = [e for e in events if e.get("country") == cc]
        srcs = sorted({e.get("sourcetype") for e in evs})
        return (f"<p>Found <b>{len(evs)}</b> events from <code>{cc}</code>"
                + (" ⚠️ (high-risk geo)" if cc in HOSTILE else "") + ". "
                + (f"Sources: {', '.join(srcs)}." if evs else "") + "</p>"
                + f'<p class="muted">Tip: run <code>country={cc}</code> in Search for the full list.</p>')

    if re.search(r"how many|count|number of", q):
        c = ", ".join(f'{len([f for f in findings if f["severity"]==s])} {s}'
                      for s in ["critical", "high", "medium", "low"])
        return f"<p><b>{len(events):,}</b> total events. Findings: {c}.</p>"

    # optional LLM fallback
    if os.getenv("OPENAI_API_KEY"):
        try:
            return _llm(question, events, findings)
        except Exception:
            pass

    return ("<p>I'm your security analyst. I can summarize the threat posture, explain specific "
            "detections, recommend response actions, and query the data.</p>"
            '<p class="muted">Try: "give me a summary", "what should I do about the brute force", '
            '"top source IPs", "events from CN".</p>')


def _llm(question, events, findings):
    from openai import OpenAI
    client = OpenAI()
    ctx = "Findings:\n" + "\n".join(f"- [{f['severity']}] {f['title']}: {f['evidence']}" for f in findings[:15])
    r = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": "You are a SOC security analyst. Answer concisely using only the provided findings/context. Use short HTML (<p>, <ul>, <b>)."},
            {"role": "user", "content": f"{ctx}\n\nQuestion: {question}"},
        ], temperature=0.2, max_tokens=400)
    return r.choices[0].message.content
