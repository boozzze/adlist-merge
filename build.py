#!/usr/bin/env python3
"""Собирает один дедуплицированный список доменов из нескольких блок-листов.

Оставляет только правила, которые AdGuard Home реально умеет применять на DNS-уровне:
  ||domain^            -> блокировка
  ||domain^$modifier   -> блокировка (модификатор отбрасывается)
  @@||domain^          -> исключение
  0.0.0.0 domain       -> hosts-формат

Косметика (##), path-правила (/ads/*), regex и wildcard-правила отбрасываются:
в DNS они не работают, но занимают память.
"""

from __future__ import annotations

import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OUT_DIR = Path("out")

# name -> (url, входит ли в "fit"-вариант)
SOURCES: dict[str, tuple[str, bool]] = {
    "HaGeZi Pro": (
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt",
        True,
    ),
    "AdGuard DNS filter": (
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        False,
    ),
    "1Hosts Lite": (
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt",
        False,
    ),
    "ShadowWhisperer Malware": (
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
        False,
    ),
    "AWAvenue Ads Rule": (
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt",
        True,
    ),
    "HaGeZi Windows/Office": (
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
        True,
    ),
    "Smart-TV": (
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
        True,
    ),
    "RU AdList: adservers": (
        "https://raw.githubusercontent.com/easylist/ruadlist/master/advblock/adservers.txt",
        True,
    ),
    "RU AdList: general_block": (
        "https://raw.githubusercontent.com/easylist/ruadlist/master/advblock/general_block.txt",
        True,
    ),
    "RU AdList: thirdparty": (
        "https://raw.githubusercontent.com/easylist/ruadlist/master/advblock/thirdparty.txt",
        True,
    ),
}

# Исключения берём только из RU AdList: чужие @@ конфликтуют между листами
# и снимают блокировки друг друга.
ALLOW_SOURCES = {
    "RU AdList: whitelist": (
        "https://raw.githubusercontent.com/easylist/ruadlist/master/advblock/whitelist.txt"
    ),
}

DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9._-]+)\^(?:\$.*)?$", re.IGNORECASE)
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)$")


def fetch(url: str, attempts: int = 3) -> str:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "adlist-merge/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            last = exc
    raise RuntimeError(f"не удалось скачать {url}: {last}")


def valid(domain: str) -> bool:
    domain = domain.strip(".").lower()
    if not domain or len(domain) > 253 or "_" in domain:
        return False
    return bool(DOMAIN_RE.match(domain))


def parse(text: str, allow_file: bool = False) -> tuple[set[str], set[str]]:
    block: set[str] = set()
    allow: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "!#[":
            continue

        is_allow = line.startswith("@@")
        if is_allow:
            line = line[2:].strip()
            if not allow_file:
                # чужие исключения не тащим
                continue

        match = ADBLOCK_RE.match(line)
        if match:
            domain = match.group(1).lower()
        else:
            match = HOSTS_RE.match(line)
            if not match:
                continue
            domain = match.group(1).lower()

        if not valid(domain):
            continue
        (allow if is_allow else block).add(domain)

    return block, allow


def render(title: str, domains: list[str], allows: list[str], sources: list[str]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        f"! {title}",
        "! Собрано автоматически: https://github.com/ (GitHub Actions)",
        f"! Обновлено: {now}",
        f"! Правил: {len(domains) + len(allows)} "
        f"(блокировок {len(domains)}, исключений {len(allows)})",
        "! Источники:",
        *(f"!   {s}" for s in sources),
        "",
    ]
    body = [f"||{d}^" for d in domains] + [f"@@||{d}^" for d in allows]
    return "\n".join(header + body) + "\n"


def build() -> None:
    OUT_DIR.mkdir(exist_ok=True)

    allows: set[str] = set()
    for name, url in ALLOW_SOURCES.items():
        block, allow = parse(fetch(url), allow_file=True)
        allows |= allow
        print(f"{name}: {len(allow)} исключений")

    full: set[str] = set()
    fit: set[str] = set()
    used_full: list[str] = []
    used_fit: list[str] = []

    for name, (url, in_fit) in SOURCES.items():
        block, _ = parse(fetch(url))
        block -= allows
        print(f"{name}: {len(block)} доменов")
        full |= block
        used_full.append(name)
        if in_fit:
            fit |= block
            used_fit.append(name)

    fit_allows = allows & fit
    full_allows = allows
    fit -= fit_allows
    full -= full_allows

    (OUT_DIR / "full.txt").write_text(
        render("ALL lists (full)", sorted(full), sorted(full_allows), used_full),
        encoding="utf-8",
    )
    (OUT_DIR / "fit.txt").write_text(
        render("Fit for 256-512 MB routers (fit)", sorted(fit), sorted(fit_allows), used_fit),
        encoding="utf-8",
    )
    print(f"full.txt: {len(full) + len(full_allows)} правил")
    print(f"fit.txt:  {len(fit) + len(fit_allows)} правил")


if __name__ == "__main__":
    sys.exit(build())
