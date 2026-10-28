#!/usr/bin/env python3
"""SysParallax Discord Control Center, run from trusted main via GitHub Actions.

Stdlib only. Bot sends a single pinned Discord message and edits it on updates.
No PR code is executed; all GitHub reads use a read-only GITHUB_TOKEN.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

API_GITHUB = "https://api.github.com"
API_DISCORD = "https://discord.com/api/v10"
USER_AGENT = "DiscordBot (https://github.com/SysParallax/SysParallax, 1.0)"
MARKER = "SysParallax Control Center v1"
GOOD = 0x2ECC71
BAD = 0xE74C3C
WAIT = 0xF1C40F
NEUTRAL = 0x5865F2


class ApiError(RuntimeError):
    def __init__(self, status: int, reason: str):
        self.status = status
        super().__init__(f"HTTP {status}: {reason[:240]}")


def request_json(url: str, *, token: str = "", method: str = "GET", payload: dict | None = None,
                 is_discord: bool = False) -> Any:
    """Send authenticated JSON requests. Never include tokens in URLs or errors."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json" if is_discord else "application/vnd.github+json",
    }
    if is_discord:
        headers["Authorization"] = f"Bot {token}"
    else:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    for attempt in range(4):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                raw = resp.read(2_000_000)
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(2000)
                details = json.loads(body.decode("utf-8"))
                reason = str(details.get("message", "API error")) if isinstance(details, dict) else "API error"
            except (ValueError, UnicodeDecodeError):
                reason = "API error"
            if exc.code == 429 and attempt < 3:
                retry_after = exc.headers.get("Retry-After", "1")
                try:
                    delay = min(8, max(0.1, float(retry_after)))
                except ValueError:
                    delay = 1
                time.sleep(delay)
                continue
            if exc.code >= 500 and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            raise ApiError(exc.code, reason) from None
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < 3:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"Service distant inaccessible ({type(exc).__name__})") from None
    raise RuntimeError("Nombre maximal de tentatives HTTP atteint")


def clean(value: str, limit: int = 90) -> str:
    """Remove linebreaks, mentions and markdown formatting from GitHub user titles."""
    value = re.sub(r"\s+", " ", str(value))
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    value = value.replace("@", "＠").replace("<", "‹").replace(">", "›")
    value = re.sub(r"([\\`*_~|\[\]])", r"\\\1", value)
    return value[: limit - 1] + "…" if len(value) > limit else value


def gh(path: str) -> Any:
    return request_json(f"{API_GITHUB}{path}", token=os.environ["GITHUB_TOKEN"])


def safe_gh(path: str) -> Any | None:
    try:
        return gh(path)
    except ApiError as exc:
        if exc.status == 404:
            return None
        raise


def workflow_status(repo: str, filename: str, title: str) -> dict:
    parts = repo.split("/", 1)
    path = "/".join(urllib.parse.quote(p, safe="") for p in parts)
    url = f"https://github.com/{repo}/actions/workflows/{filename}"
    data = gh(f"/repos/{path}/actions/workflows/{filename}/runs?branch=main&per_page=1")
    runs = data.get("workflow_runs", [])
    if not runs:
        return {"label": title, "status": "unknown", "line": f"⚪ [Non exécuté]({url})"}
    run = runs[0]
    status = run.get("status")
    conclusion = run.get("conclusion")
    if status != "completed":
        symbol, label, state = "🟡", "En cours", "waiting"
    elif conclusion == "success":
        symbol, label, state = "🟢", "Réussi", "success"
    elif conclusion in {"cancelled", "skipped", "neutral"}:
        symbol, label, state = "⚪", "Annulé / ignoré", "unknown"
    else:
        symbol, label, state = "🔴", "Échec", "failure"
    run_url = run.get("html_url") or url
    if not isinstance(run_url, str) or not run_url.startswith("https://github.com/"):
        run_url = url
    branch = clean(run.get("head_branch") or "main", 28)
    return {"label": title, "status": state,
            "line": f"{symbol} **[{label}]({run_url})** · `{branch}`"}


def issue_summary(repo: str, kind: str) -> tuple[int, str]:
    q = f"repo:{repo} is:{kind} is:open"
    query = urllib.parse.urlencode({"q": q, "sort": "updated", "order": "desc", "per_page": 3})
    data = gh(f"/search/issues?{query}")
    total = int(data.get("total_count", 0))
    items = []
    for issue in data.get("items", []):
        n = issue.get("number", "?")
        label = clean(issue.get("title", "Sans titre"), 72)
        url = issue.get("html_url")
        if not isinstance(url, str) or not url.startswith(f"https://github.com/{repo}/"):
            continue
        items.append(f"• [#{n} {label}]({url})")
    return total, "\n".join(items) if items else "Aucun élément ouvert"


def release_summary(repo: str) -> str:
    data = safe_gh(f"/repos/{repo}/releases/latest")
    if not data:
        return "Aucune release publiée"
    tag = clean(data.get("tag_name", "?"), 70)
    url = data.get("html_url", "")
    if not isinstance(url, str) or not url.startswith(f"https://github.com/{repo}/releases/"):
        return tag
    return f"📦 [{tag}]({url})"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def service_summary(raw: str) -> str:
    """Optional public HTTPS checks (no auth, no redirects, no private endpoints)."""
    if not raw.strip():
        return "⚪ Aucun endpoint de santé déclaré"
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SYSPARALLAX_HEALTHCHECKS doit être un objet JSON") from exc
    if not isinstance(config, dict) or len(config) > 5:
        raise ValueError("SYSPARALLAX_HEALTHCHECKS: objet JSON, max. 5 services")
    results = []
    opener = urllib.request.build_opener(NoRedirect)
    for name, target in config.items():
        label = clean(str(name), 35)
        if not isinstance(target, str) or not target.startswith("https://"):
            results.append(f"⚪ {label} — endpoint HTTPS invalide")
            continue
        # Only configured public health URLs. No secrets or query tokens in repo variables.
        parsed = urllib.parse.urlsplit(target)
        if (not parsed.hostname or parsed.username or parsed.password or
                parsed.port not in (None, 443) or
                parsed.hostname.lower() in {"localhost"} or
                parsed.hostname.endswith((".local", ".internal", ".localhost"))):
            results.append(f"⚪ {label} — endpoint non autorisé")
            continue
        try:
            req = urllib.request.Request(target, headers={"User-Agent": USER_AGENT})
            with opener.open(req, timeout=5) as response:
                healthy = 200 <= response.status < 300
            results.append(f"{'🟢' if healthy else '🔴'} {label} — {'OK' if healthy else 'Indisponible'}")
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
            results.append(f"🔴 {label} — Indisponible")
    return "\n".join(results) or "⚪ Aucun endpoint déclaré"


def build_payload(repo: str) -> dict:
    ci = workflow_status(repo, "ci.yml", "CI / Tests")
    sec = workflow_status(repo, "security.yml", "Sécurité")
    issues_count, issues_text = issue_summary(repo, "issue")
    prs_count, prs_text = issue_summary(repo, "pr")
    latest_release = release_summary(repo)
    services_text = service_summary(os.environ.get("SYSPARALLAX_HEALTHCHECKS", ""))
    states = [ci["status"], sec["status"]]
    color = BAD if "failure" in states else WAIT if "waiting" in states else GOOD if states == ["success", "success"] else NEUTRAL
    timestamp = int(datetime.now(timezone.utc).timestamp())
    return {
        "content": "📍 **SysParallax — Centre de supervision**",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": "🧭 SysParallax • Control Center",
            "url": f"https://github.com/{repo}",
            "description": "Statuts GitHub, suivi des développements et disponibilité des services. Mise à jour automatique.",
            "color": color,
            "fields": [
                {"name": "🔧 CI / Tests", "value": ci["line"], "inline": True},
                {"name": "🛡️ Sécurité", "value": sec["line"], "inline": True},
                {"name": f"🎫 Tickets ouverts — {issues_count}", "value": issues_text[:1024], "inline": False},
                {"name": f"🔀 PR ouvertes — {prs_count}", "value": prs_text[:1024], "inline": False},
                {"name": "📦 Dernière release", "value": latest_release, "inline": False},
                {"name": "🌐 Services (healthchecks)", "value": services_text[:1024], "inline": False},
                {"name": "🔗 Accès rapide", "value":
                    f"[Issues](https://github.com/{repo}/issues) · [Pull requests](https://github.com/{repo}/pulls) · "
                    f"[Projects](https://github.com/orgs/{repo.split('/')[0]}/projects) · [Actions](https://github.com/{repo}/actions)",
                    "inline": False},
            ],
            "footer": {"text": MARKER},
            "timestamp": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        }],
    }


def discord(path: str, token: str, *, method: str = "GET", payload: dict | None = None) -> Any:
    return request_json(f"{API_DISCORD}{path}", token=token, method=method,
                        payload=payload, is_discord=True)


def is_own_dashboard(msg: dict, bot_id: str) -> bool:
    if str(msg.get("author", {}).get("id", "")) != bot_id:
        return False
    for embed in msg.get("embeds", []):
        if embed.get("footer", {}).get("text") == MARKER:
            return True
    return False


def locate_message(channel: str, token: str, bot_id: str) -> tuple[str | None, bool]:
    """Prefer pinned messages; fall back to last 100 if initial pin failed."""
    base = f"/channels/{channel}"
    before = None
    for _ in range(5):  # Discord permits 250 pins / channel
        query = "?limit=50" + ("&before=" + urllib.parse.quote(before) if before else "")
        data = discord(base + "/messages/pins" + query, token)
        for item in data.get("items", []):
            msg = item.get("message", {})
            if is_own_dashboard(msg, bot_id):
                return str(msg["id"]), True
        if not data.get("has_more") or not data.get("items"):
            break
        before = data["items"][-1].get("pinned_at")
        if not before:
            break
    messages = discord(base + "/messages?limit=100", token)
    for msg in messages:
        if is_own_dashboard(msg, bot_id):
            return str(msg["id"]), False
    return None, False


def publish(channel: str, token: str, payload: dict) -> str:
    self_user = discord("/users/@me", token)
    bot_id = str(self_user.get("id", ""))
    if not bot_id:
        raise RuntimeError("Impossible de récupérer l'identité du bot Discord")
    message_id, was_pinned = locate_message(channel, token, bot_id)
    base = f"/channels/{channel}/messages"
    if message_id:
        discord(f"{base}/{message_id}", token, method="PATCH", payload=payload)
        if not was_pinned:
            try:
                discord(f"{base}/pins/{message_id}", token, method="PUT")
                print("Message retrouvé et épinglé.")
            except ApiError as exc:
                print(f"ATTENTION : impossible d’épingler le message ({exc})", file=sys.stderr)
        print(f"Control Center mis à jour : message Discord {message_id}")
        return message_id
    result = discord(base, token, method="POST", payload=payload)
    message_id = str(result["id"])
    print(f"Nouveau Control Center créé : message Discord {message_id}")
    try:
        discord(f"{base}/pins/{message_id}", token, method="PUT")
        print("Message épinglé.")
    except ApiError as exc:
        # Next run can still discover it among last 100 messages.
        print(f"ATTENTION : message créé mais épinglage refusé ({exc}). "
              "Donner au bot l'autorisation Pin Messages pour éviter les doublons.", file=sys.stderr)
    return message_id


def main() -> None:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("GITHUB_REPOSITORY invalide")
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    bot_token = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
    channel = os.environ.get("DISCORD_CONTROL_CENTER_CHANNEL_ID", "").strip()
    if not gh_token or not bot_token:
        raise ValueError("Configurer GITHUB_TOKEN et le secret DISCORD_BOT_TOKEN")
    if not re.fullmatch(r"\d{15,24}", channel):
        raise ValueError("Configurer la variable DISCORD_CONTROL_CENTER_CHANNEL_ID (identifiant numérique du salon)")
    payload = build_payload(repo)
    message_id = publish(channel, bot_token, payload)
    print(f"Control Center publié dans le salon {channel}, message {message_id}")


if __name__ == "__main__":
    try:
        main()
    except (ApiError, ValueError, RuntimeError) as exc:
        print(f"ERROR Control Center : {exc}", file=sys.stderr)
        sys.exit(1)
