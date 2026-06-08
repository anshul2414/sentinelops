"""SPL-like search engine operating on event dicts.
Supports field=value / != / > / < / >= / <=, wildcards, AND/OR/NOT,
and piped commands: search, where, head, tail, dedup, sort, fields/table,
top, rare, stats (count/sum/avg/min/max/dc [by ...]), timechart."""
import re
import shlex

OPS = [">=", "<=", "!=", "=", ">", "<"]


def tokenize(s):
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


def parse_pred(tok):
    for op in OPS:
        i = tok.find(op)
        if i > 0:
            return {"field": tok[:i], "op": op, "value": tok[i + len(op):]}
    return {"text": tok}


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def cmp(a, op, b):
    na, nb = _num(a), _num(b)
    numeric = na is not None and nb is not None
    sa = str(a)
    if op == "=":
        if "*" in b:
            rx = "^" + re.escape(b).replace(r"\*", ".*") + "$"
            return re.match(rx, sa, re.I) is not None
        return sa.lower() == str(b).lower()
    if op == "!=":
        return sa.lower() != str(b).lower()
    if op == ">":
        return na > nb if numeric else sa > b
    if op == "<":
        return na < nb if numeric else sa < b
    if op == ">=":
        return na >= nb if numeric else sa >= b
    if op == "<=":
        return na <= nb if numeric else sa <= b
    return False


def match_term(ev, term):
    t = term.lower()
    for k, v in ev.items():
        if k in ("_id", "_time"):
            continue
        if t in str(v).lower():
            return True
    return False


def filter_events(events, q):
    toks = tokenize(q.strip())
    if not toks or (len(toks) == 1 and toks[0] == "*"):
        return list(events)
    preds = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.upper() == "AND":
            i += 1; continue
        if t.upper() == "OR":
            if preds:
                preds[-1]["or"] = True
            i += 1; continue
        neg = False
        if t.upper() == "NOT":
            neg = True; i += 1
            if i >= len(toks):
                break
            t = toks[i]
        p = parse_pred(t); p["neg"] = neg
        preds.append(p); i += 1

    def ok_one(ev, p):
        if "text" in p:
            r = match_term(ev, p["text"])
        else:
            r = p["field"] in ev and cmp(ev[p["field"]], p["op"], p["value"])
        return (not r) if p.get("neg") else r

    def passes(ev):
        # split into OR groups; AND within group
        groups, cur = [], []
        for p in preds:
            cur.append(p)
            if p.get("or"):
                groups.append(cur); cur = []
        groups.append(cur)
        return any(all(ok_one(ev, p) for p in g) for g in groups if g)

    return [e for e in events if passes(e)]


def _agg(rows, fn, field):
    if fn == "count":
        return len(rows)
    if fn == "dc":
        return len({r.get(field) for r in rows})
    nums = [n for n in (_num(r.get(field)) for r in rows) if n is not None]
    if fn == "sum":
        return sum(nums)
    if fn == "avg":
        return round(sum(nums) / len(nums), 2) if nums else 0
    if fn == "min":
        return min(nums) if nums else 0
    if fn == "max":
        return max(nums) if nums else 0
    return len(rows)


def apply_cmd(data, cmd):
    parts = cmd.split()
    name = parts[0].lower()
    arg = cmd[len(parts[0]):].strip()
    rows = data["rows"]

    if name == "search":
        return {"type": "events", "rows": filter_events(rows, arg)}
    if name == "where":
        p = parse_pred(arg.split()[0])
        return {"type": data["type"], "rows": [r for r in rows if "field" in p and cmp(r.get(p["field"]), p["op"], p["value"])], "columns": data.get("columns")}
    if name == "head":
        n = int(arg) if arg.isdigit() else 10
        return {"type": data["type"], "rows": rows[:n], "columns": data.get("columns")}
    if name == "tail":
        n = int(arg) if arg.isdigit() else 10
        return {"type": data["type"], "rows": rows[-n:], "columns": data.get("columns")}
    if name == "dedup":
        seen, out = set(), []
        for r in rows:
            k = r.get(arg)
            if k not in seen:
                seen.add(k); out.append(r)
        return {"type": data["type"], "rows": out, "columns": data.get("columns")}
    if name == "sort":
        f = arg; desc = False
        if f.startswith("-"):
            desc = True; f = f[1:]
        def key(r):
            n = _num(r.get(f))
            return (0, n) if n is not None else (1, str(r.get(f)))
        return {"type": data["type"], "rows": sorted(rows, key=key, reverse=desc), "columns": data.get("columns")}
    if name in ("fields", "table"):
        cols = [c for c in re.split(r"[,\s]+", arg) if c]
        return {"type": "table", "rows": [{c: r.get(c) for c in cols} for r in rows], "columns": cols}
    if name in ("top", "rare"):
        f = arg.split()[0]
        counts = {}
        for r in rows:
            k = r.get(f, "(null)")
            counts[k] = counts.get(k, 0) + 1
        items = sorted(counts.items(), key=lambda kv: kv[1], reverse=(name == "top"))[:10]
        return {"type": "table", "rows": [{f: k, "count": v} for k, v in items], "columns": [f, "count"]}
    if name == "stats":
        low = arg.lower()
        by_i = low.find(" by ")
        agg_str = arg[:by_i] if by_i >= 0 else arg
        by_fields = [x for x in re.split(r"[,\s]+", arg[by_i + 4:].strip()) if x] if by_i >= 0 else []
        aggs = []
        for a in [x for x in re.split(r"[,\s]+", agg_str) if x]:
            m = re.match(r"^(\w+)\(([^)]*)\)$", a)
            if m:
                aggs.append({"fn": m.group(1).lower(), "field": m.group(2), "label": a})
            else:
                aggs.append({"fn": a.lower(), "field": None, "label": a})
        cols = by_fields + [a["label"] for a in aggs]
        if not by_fields:
            row = {a["label"]: _agg(rows, a["fn"], a["field"]) for a in aggs}
            return {"type": "table", "rows": [row], "columns": cols}
        groups = {}
        for r in rows:
            key = tuple(str(r.get(f, "(null)")) for f in by_fields)
            groups.setdefault(key, []).append(r)
        out = []
        for key, grp in groups.items():
            o = {f: key[i] for i, f in enumerate(by_fields)}
            for a in aggs:
                o[a["label"]] = _agg(grp, a["fn"], a["field"])
            out.append(o)
        sort_col = aggs[0]["label"] if aggs else cols[-1]
        out.sort(key=lambda r: _num(r.get(sort_col)) or 0, reverse=True)
        return {"type": "table", "rows": out, "columns": cols}
    if name == "timechart":
        span = 3600000
        m = re.search(r"span=(\d+)(m|h|d)", arg)
        if m:
            span = int(m.group(1)) * (60000 if m.group(2) == "m" else 86400000 if m.group(2) == "d" else 3600000)
        buckets = {}
        for r in rows:
            b = (r.get("_time", 0) // span) * span
            buckets[b] = buckets.get(b, 0) + 1
        out = [{"_time": t, "count": c} for t, c in sorted(buckets.items())]
        return {"type": "timechart", "rows": out, "columns": ["_time", "count"], "span": span}
    return data


def run(events, query):
    pipes = [p.strip() for p in query.split("|") if p.strip()]
    if not pipes:
        return {"type": "events", "rows": list(events)}
    data = {"type": "events", "rows": filter_events(events, pipes[0])}
    for seg in pipes[1:]:
        data = apply_cmd(data, seg)
    return data
