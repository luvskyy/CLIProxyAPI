#!/usr/bin/env python3
"""CLIProxyAPI usage dashboard.

Serves a single page plus JSON endpoints on loopback. Reads the ClickHouse
`usage` table written by the observability.clickhouse sink and the proxy's
management API for live credential state. Request/response bodies are never
exposed here; query cliproxy.bodies directly with clickhouse client.

Env: CLICKHOUSE_PASSWORD, CPA_MANAGEMENT_KEY (sourced from ~/.config/cliproxy/env)
     DASH_PORT (default 8318), CH_URL, CPA_URL, CH_DB
"""
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CH_URL = os.environ.get("CH_URL", "http://127.0.0.1:8123/")
CH_DB = os.environ.get("CH_DB", "cliproxy")
CPA_URL = os.environ.get("CPA_URL", "http://127.0.0.1:8317")
PORT = int(os.environ.get("DASH_PORT", "8318"))
HERE = os.path.dirname(os.path.abspath(__file__))

RANGES = {"1h": "1 HOUR", "24h": "24 HOUR", "7d": "7 DAY", "30d": "30 DAY"}
BUCKETS = {"1h": "toStartOfFiveMinutes", "24h": "toStartOfHour", "7d": "toStartOfHour", "30d": "toStartOfDay"}
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def ch(sql):
    req = urllib.request.Request(
        CH_URL + "?" + urllib.parse.urlencode({"database": CH_DB, "default_format": "JSON"}),
        data=sql.encode(),
        headers={"X-ClickHouse-User": "default", "X-ClickHouse-Key": os.environ.get("CLICKHOUSE_PASSWORD", "")},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)["data"]


def management(path):
    req = urllib.request.Request(CPA_URL + path, headers={"Authorization": "Bearer " + os.environ.get("CPA_MANAGEMENT_KEY", "")})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def client_names():
    """Map client_key_id (sha256[:12], same as the sink) to friendly names from env keys."""
    names = {"CPA_CLAUDE_CODE_KEY": "claude-code", "CPA_GENERAL_KEY": "general"}
    return {hashlib.sha256(os.environ[k].encode()).hexdigest()[:12]: v for k, v in names.items() if os.environ.get(k)}


def summary(rng):
    window = RANGES[rng]
    bucket = BUCKETS[rng]
    where = f"requested_at > now() - INTERVAL {window}"
    totals = ch(f"""
        SELECT count() requests, countIf(failed=1) failures,
               sum(input_tokens) input, sum(output_tokens) output,
               sum(cache_read_tokens + cached_tokens) cached, sum(reasoning_tokens) reasoning,
               round(quantile(0.5)(latency_ms)) p50_ms, round(quantile(0.95)(latency_ms)) p95_ms
        FROM usage WHERE {where}""")
    by_model = ch(f"""
        SELECT provider, model, count() requests, countIf(failed=1) failures,
               sum(input_tokens) input, sum(output_tokens) output,
               sum(cache_read_tokens + cached_tokens) cached,
               round(quantile(0.5)(latency_ms)) p50_ms, round(avgIf(ttft_ms, ttft_ms > 0)) ttft_ms
        FROM usage WHERE {where}
        GROUP BY provider, model ORDER BY input + output DESC LIMIT 60""")
    series = ch(f"""
        SELECT toUnixTimestamp({bucket}(requested_at)) t, provider,
               count() requests, sum(input_tokens + output_tokens) tokens
        FROM usage WHERE {where}
        GROUP BY t, provider ORDER BY t""")
    by_client = ch(f"""
        SELECT client_key_id, count() requests, sum(input_tokens + output_tokens) tokens
        FROM usage WHERE {where} GROUP BY client_key_id ORDER BY tokens DESC""")
    recent = ch("""
        SELECT formatDateTime(requested_at, '%Y-%m-%d %H:%i:%S', 'America/New_York') at, provider, model,
               client_key_id, input_tokens, output_tokens, latency_ms, failed, status_code, error_code
        FROM usage ORDER BY requested_at DESC LIMIT 40""")
    return {"totals": totals[0] if totals else {}, "by_model": by_model, "series": series,
            "by_client": by_client, "recent": recent}


def limits():
    """Latest rate-limit / credit headers per credential, from ClickHouse plus live management state."""
    rows = ch("""
        SELECT provider, auth_id, max(requested_at) last_seen,
               argMax(response_headers, requested_at) headers
        FROM usage WHERE length(mapKeys(response_headers)) > 0
          AND requested_at > now() - INTERVAL 8 DAY
        GROUP BY provider, auth_id""")
    out = {}
    for r in rows:
        keep = {k: v for k, v in r["headers"].items()
                if re.search(r"ratelimit|rate-limit|credit|limit|quota|usage", k, re.I)}
        out[r["auth_id"]] = {"provider": r["provider"], "last_seen": r["last_seen"], "signals": keep}
    creds = []
    try:
        files = management("/v0/management/auth-files").get("files", [])
    except Exception as exc:  # proxy down: still show stored signals
        files = []
        creds.append({"error": f"management API unavailable: {exc}"})
    seen = set()
    for f in files:
        auth_id = f.get("id", "")
        seen.add(auth_id)
        live = {}
        for q in (f.get("model_quotas") or {}).values():
            live.update(q.get("signals") or {})
        live.update((f.get("quota") or {}).get("signals") or {})
        stored = out.get(auth_id, {})
        signals = dict(stored.get("signals", {}))
        signals.update(live)
        creds.append({
            "provider": f.get("provider"), "label": EMAIL.sub(lambda m: m.group(0)[:3] + "…", f.get("label", auth_id)),
            "auth_id_hint": auth_id[:18], "disabled": f.get("disabled"), "failed": f.get("failed"),
            "cooldowns": [{"model": c.get("model_key"), "reason": c.get("reason"), "remaining_s": c.get("remaining_seconds")}
                          for c in f.get("cooldowns") or []],
            "recent": f.get("recent_requests") or [], "last_seen": stored.get("last_seen"), "signals": signals,
        })
    for auth_id, v in out.items():
        if auth_id not in seen:
            creds.append({"provider": v["provider"], "label": EMAIL.sub("…", auth_id)[:40], "signals": v["signals"],
                          "last_seen": v["last_seen"], "cooldowns": [], "recent": []})
    return {"credentials": creds}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(url.query)
        try:
            if url.path == "/":
                with open(os.path.join(HERE, "index.html"), "rb") as fh:
                    return self.send(200, fh.read(), "text/html; charset=utf-8")
            if url.path == "/api/summary":
                rng = qs.get("range", ["24h"])[0]
                if rng not in RANGES:
                    return self.send(400, '{"error":"bad range"}', "application/json")
                return self.send(200, json.dumps(summary(rng), default=str), "application/json")
            if url.path == "/api/limits":
                return self.send(200, json.dumps(limits(), default=str), "application/json")
            if url.path == "/api/clients":
                return self.send(200, json.dumps(client_names()), "application/json")
            if url.path == "/healthz":
                return self.send(200, "ok", "text/plain")
            return self.send(404, "not found", "text/plain")
        except Exception as exc:
            return self.send(502, json.dumps({"error": str(exc)}), "application/json")


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
