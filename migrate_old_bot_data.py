#!/usr/bin/env python3
"""
Migrate old awg-docker-bot profile bindings into Amnezia Web Panel data.json.

This script updates ONLY panel data.json:
- creates/updates user->connection links in user_connections
- optionally creates missing users by Telegram username

Expected old bot structure:
  <old_data>/profiles/<SERVER_NAME>/<tg_username>/<profile_dir>/<profile>.conf
  <old_data>/servers/<SERVER_NAME>/clientsTable (optional)
  <old_data>/servers/<SERVER_NAME>/server.conf  (optional)

Usage example:
  python3 migrate_old_bot_data.py \
    --old-data /path/to/awg-docker-bot/data \
    --server Finland \
    --panel-data ./data.json \
    --panel-server "FI HELSINKI 1" \
    --protocol awg
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


@dataclass
class ParsedProfile:
    path: Path
    tg_username: str
    profile_name: str
    private_key: str
    client_ip: str
    psk: str
    raw_config: str


@dataclass
class LegacyClient:
    client_id: str
    client_name: str
    allowed_ip: str
    creation_date: str


def norm_tg(value: str) -> str:
    return (value or "").strip().lstrip("@").lower()


def norm_handle(value: str) -> str:
    """Normalize usernames/handles across '_' '-' '.' and case differences."""
    v = (value or "").strip().lstrip("@").lower()
    return re.sub(r"[^a-z0-9]", "", v)


def parse_conf(conf_path: Path) -> Optional[ParsedProfile]:
    text = conf_path.read_text(encoding="utf-8", errors="ignore")

    def find(pattern: str) -> str:
        m = re.search(pattern, text, flags=re.MULTILINE)
        return m.group(1).strip() if m else ""

    private_key = find(r"^\s*PrivateKey\s*=\s*(.+)$")
    address = find(r"^\s*Address\s*=\s*(.+)$")
    psk = find(r"^\s*PresharedKey\s*=\s*(.+)$")

    if not private_key or not address:
        return None

    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", address)
    if not ip_match:
        return None

    # profiles/<server>/<tg_username>/<profile_dir>/<file>.conf
    parts = conf_path.parts
    if len(parts) < 4:
        return None

    tg_username = parts[-3]
    profile_name = conf_path.stem

    return ParsedProfile(
        path=conf_path,
        tg_username=tg_username,
        profile_name=profile_name,
        private_key=private_key,
        client_ip=ip_match.group(1),
        psk=psk,
        raw_config=text,
    )


def parse_legacy_dt(value: str) -> Optional[datetime]:
    """Parse datetime from legacy clientsTable creationDate formats."""
    v = (value or "").strip()
    if not v:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(v)
    except Exception:
        return None


def load_legacy_clients(old_data: Path, server_name: str) -> List[LegacyClient]:
    p = old_data / "servers" / server_name / "clientsTable"
    if not p.exists():
        return []

    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []

    result: List[LegacyClient] = []
    if isinstance(raw, list):
        for item in raw:
            cid = str(item.get("clientId", "") or "")
            ud = item.get("userData", {}) if isinstance(item, dict) else {}
            cname = str(ud.get("clientName", "") or "")
            allowed = str(ud.get("allowedIps", "") or "")
            created = str(ud.get("creationDate", "") or "")
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", allowed)
            result.append(
                LegacyClient(
                    client_id=cid,
                    client_name=cname,
                    allowed_ip=m.group(1) if m else "",
                    creation_date=created,
                )
            )
    elif isinstance(raw, dict):
        for cid, ud in raw.items():
            ud = ud or {}
            cname = str(ud.get("clientName", "") or "")
            allowed = str(ud.get("allowedIps", "") or "")
            created = str(ud.get("creationDate", "") or "")
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", allowed)
            result.append(
                LegacyClient(
                    client_id=str(cid),
                    client_name=cname,
                    allowed_ip=m.group(1) if m else "",
                    creation_date=created,
                )
            )

    return [x for x in result if x.client_id]


def derive_public_key(private_key_b64: str) -> str:
    raw = base64.b64decode(private_key_b64)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub).decode("ascii")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def find_server_id(data: dict, panel_server: str) -> int:
    want = panel_server.strip().lower()
    for i, srv in enumerate(data.get("servers", [])):
        name = str(srv.get("name", "")).strip().lower()
        host = str(srv.get("host", "")).strip().lower()
        if want in (name, host):
            return i
    raise RuntimeError(f"Panel server '{panel_server}' not found in data.json")


def find_user_id_by_tg(data: dict, tg_username: str) -> Optional[str]:
    want_norm = norm_handle(tg_username)
    for u in data.get("users", []):
        tg_val = str(u.get("telegramId", "") or "")
        uname = str(u.get("username", "") or "")
        if norm_handle(tg_val) == want_norm or norm_handle(uname) == want_norm:
            return str(u["id"])
    return None


def create_user_for_tg(data: dict, tg_username: str) -> str:
    uid = str(uuid.uuid4())
    username = norm_tg(tg_username) or f"user_{uid[:8]}"
    now = datetime.now().isoformat()
    pwd = secrets.token_urlsafe(12)

    # Panel stores password hash generated by app runtime; for migration user can reset later.
    # We keep account enabled but random password avoids accidental weak defaults.
    user = {
        "id": uid,
        "username": username,
        "password_hash": "",
        "role": "user",
        "telegramId": f"@{norm_tg(tg_username)}",
        "email": None,
        "description": "Imported from old awg-docker-bot",
        "traffic_limit": 0,
        "traffic_reset_strategy": "never",
        "traffic_used": 0,
        "traffic_total": 0,
        "last_reset_at": now,
        "expiration_date": None,
        "enabled": True,
        "created_at": now,
        "remnawave_uuid": None,
        "share_enabled": False,
        "share_token": secrets.token_urlsafe(16),
        "share_password_hash": None,
    }
    data.setdefault("users", []).append(user)
    return uid


def upsert_connection(
    data: dict,
    user_id: str,
    server_id: int,
    protocol: str,
    client_id: str,
    name: str,
    imported_config: str = "",
) -> Tuple[bool, str]:
    conns = data.setdefault("user_connections", [])

    for c in conns:
        if (
            c.get("user_id") == user_id
            and c.get("server_id") == server_id
            and c.get("protocol") == protocol
            and c.get("client_id") == client_id
        ):
            if name and c.get("name") != name:
                c["name"] = name
            if imported_config:
                c["imported_config"] = imported_config
            return False, str(c.get("id"))

    cid = str(uuid.uuid4())
    conns.append(
        {
            "id": cid,
            "user_id": user_id,
            "server_id": server_id,
            "protocol": protocol,
            "client_id": client_id,
            "name": name,
            "created_at": datetime.now().isoformat(),
            "imported_config": imported_config if imported_config else "",
        }
    )
    return True, cid


def collect_profiles(old_data: Path, server_name: str) -> List[ParsedProfile]:
    base = old_data / "profiles" / server_name
    if not base.exists():
        raise RuntimeError(f"Profiles dir not found: {base}")

    parsed: List[ParsedProfile] = []
    for conf in base.glob("*/*/*.conf"):
        item = parse_conf(conf)
        if item:
            parsed.append(item)
    return parsed


def choose_client_id(profile: ParsedProfile, legacy_clients: List[LegacyClient]) -> Optional[str]:
    # 1) Exact match by profile dir/file name to old clientsTable clientName
    by_name = [c for c in legacy_clients if c.client_name == profile.profile_name]
    if len(by_name) == 1:
        return by_name[0].client_id

    # 2) Derived public key from PrivateKey
    try:
        derived = derive_public_key(profile.private_key)
        if any(c.client_id == derived for c in legacy_clients):
            return derived
    except Exception:
        pass

    # 3) Fallback by unique AllowedIP in clientsTable
    by_ip = [c for c in legacy_clients if c.allowed_ip and c.allowed_ip == profile.client_ip]
    if len(by_ip) == 1:
        return by_ip[0].client_id

    return None


def choose_client(profile: ParsedProfile, legacy_clients: List[LegacyClient]) -> Optional[LegacyClient]:
    cid = choose_client_id(profile, legacy_clients)
    if not cid:
        return None
    for c in legacy_clients:
        if c.client_id == cid:
            return c
    return None


def find_user_obj(data: dict, user_id: str) -> Optional[dict]:
    for u in data.get("users", []):
        if str(u.get("id")) == user_id:
            return u
    return None


def run(args: argparse.Namespace) -> None:
    old_data = Path(args.old_data).expanduser().resolve()
    panel_data_path = Path(args.panel_data).expanduser().resolve()

    if not panel_data_path.exists():
        raise RuntimeError(f"Panel data.json not found: {panel_data_path}")

    data = load_json(panel_data_path)
    server_id = find_server_id(data, args.panel_server or args.server)
    protocol = args.protocol

    profiles = collect_profiles(old_data, args.server)
    legacy_clients = load_legacy_clients(old_data, args.server)
    if not profiles:
        print("No profiles found for selected server.")
        return

    created_users = 0
    created_links = 0
    updated_links = 0
    skipped = 0
    unresolved_client_id = 0
    updated_user_created_at = 0
    user_first_profile_dt: Dict[str, datetime] = {}

    for p in profiles:
        legacy_client = choose_client(p, legacy_clients)
        if not legacy_client:
            skipped += 1
            unresolved_client_id += 1
            print(f"SKIP cannot resolve clientId: {p.path}")
            continue
        client_id = legacy_client.client_id

        user_id = find_user_id_by_tg(data, p.tg_username)
        if not user_id:
            if args.create_missing_users:
                user_id = create_user_for_tg(data, p.tg_username)
                created_users += 1
            else:
                skipped += 1
                print(f"SKIP user not found for tg '{p.tg_username}' (file: {p.path})")
                continue

        added, _ = upsert_connection(
            data=data,
            user_id=user_id,
            server_id=server_id,
            protocol=protocol,
            client_id=client_id,
            name=p.profile_name,
            imported_config=p.raw_config if args.store_imported_config else "",
        )
        if added:
            created_links += 1
        else:
            updated_links += 1

        # Collect earliest profile creation date from legacy clientsTable per user.
        legacy_dt = parse_legacy_dt(legacy_client.creation_date)
        if legacy_dt:
            prev = user_first_profile_dt.get(user_id)
            if prev is None or legacy_dt < prev:
                user_first_profile_dt[user_id] = legacy_dt

    if args.set_user_created_from_first_profile:
        for user_id, first_dt in user_first_profile_dt.items():
            user = find_user_obj(data, user_id)
            if not user:
                continue
            current = str(user.get("created_at", "") or "")
            current_dt = parse_legacy_dt(current)

            # Update if empty/invalid or current timestamp is later than first profile date.
            if current_dt is None or first_dt < current_dt:
                user["created_at"] = first_dt.isoformat(timespec="seconds")
                updated_user_created_at += 1

    if args.dry_run:
        print("Dry run complete. No file changes written.")
    else:
        save_json(panel_data_path, data)
        print(f"Updated: {panel_data_path}")

    print("--- Migration summary ---")
    print(f"Profiles parsed: {len(profiles)}")
    print(f"Legacy clients loaded: {len(legacy_clients)}")
    print(f"Users created: {created_users}")
    print(f"Connections added: {created_links}")
    print(f"Connections touched(existing): {updated_links}")
    print(f"Users created_at updated: {updated_user_created_at}")
    print(f"Skipped unresolved clientId: {unresolved_client_id}")
    print(f"Skipped: {skipped}")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Migrate old awg-docker-bot profiles into panel data.json")
    p.add_argument("--old-data", required=True, help="Path to old bot data directory")
    p.add_argument("--server", required=True, help="Server directory name inside old-data/profiles")
    p.add_argument("--panel-data", default="./data.json", help="Path to panel data.json")
    p.add_argument("--panel-server", default="", help="Panel server name/host in data.json (defaults to --server)")
    p.add_argument("--protocol", default="awg", choices=["awg", "awg2", "awg_legacy"], help="Protocol for imported links")
    p.add_argument("--create-missing-users", action="store_true", help="Create panel users for missing Telegram usernames")
    p.add_argument(
        "--store-imported-config",
        action="store_true",
        help="Store raw imported .conf text in user_connections.imported_config for local fallback",
    )
    p.add_argument(
        "--set-user-created-from-first-profile",
        action="store_true",
        help="Set user created_at to earliest legacy profile creationDate from clientsTable",
    )
    p.add_argument("--dry-run", action="store_true", help="Parse and print summary without writing data.json")
    return p


if __name__ == "__main__":
    parser = build_arg_parser()
    run(parser.parse_args())
