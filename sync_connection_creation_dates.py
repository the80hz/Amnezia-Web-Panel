#!/usr/bin/env python3
"""
Synchronize connection creation dates between local data.json and remote clients tables.

Also supports importing creation dates from an old backup clientsTable
into a selected remote server/protocol.

Supported protocols:
- awg
- awg2
- awg_legacy
- xray

By default, local data.json -> remote clientsTable synchronization is used.
Use --direction remote-to-data to do the opposite.

Examples:
  python sync_connection_creation_dates.py --panel-data ./data.json --dry-run
  python sync_connection_creation_dates.py --panel-data ./data.json --apply
  python sync_connection_creation_dates.py --panel-data ./data.json --direction remote-to-data --apply
  python sync_connection_creation_dates.py --panel-data ./data.json --server-id 0 --protocols awg,xray --apply
  python sync_connection_creation_dates.py --panel-data ./data.json --backup-clients-table ./data_old/servers/Finland/clientsTable --server-id 0 --protocols awg --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ssh_manager import SSHManager
from awg_manager import AWGManager
from xray_manager import XrayManager

SUPPORTED_PROTOCOLS = {"awg", "awg2", "awg_legacy", "xray"}


@dataclass
class Change:
    server_id: int
    server_name: str
    protocol: str
    client_id: str
    connection_id: str
    old_value: str
    new_value: str


def parse_dt(value: str) -> Optional[datetime]:
    v = (value or "").strip()
    if not v:
        return None

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M",
    ):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        return None


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_manager(ssh: SSHManager, protocol: str):
    if protocol == "xray":
        return XrayManager(ssh)
    return AWGManager(ssh)


def get_remote_clients_table(manager: Any, protocol: str) -> Tuple[Any, Dict[str, Dict[str, Any]]]:
    if protocol == "xray":
        table = manager._get_clients_table()
    else:
        table = manager._get_clients_table(protocol)

    index: Dict[str, Dict[str, Any]] = {}

    if isinstance(table, list):
        for item in table:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("clientId", "") or "").strip()
            if not cid:
                continue
            index[cid] = item
    elif isinstance(table, dict):
        # Rare legacy shape: {clientId: {...}}
        for cid, ud in table.items():
            cid_s = str(cid or "").strip()
            if not cid_s:
                continue
            wrapper = {
                "clientId": cid_s,
                "userData": ud if isinstance(ud, dict) else {},
            }
            index[cid_s] = wrapper
    else:
        table = []

    return table, index


def save_remote_clients_table(manager: Any, protocol: str, table: Any) -> None:
    if protocol == "xray":
        manager._save_clients_table(table)
    else:
        manager._save_clients_table(protocol, table)


def load_backup_clients_table(path: Path) -> Dict[str, Dict[str, Any]]:
    raw = load_json(path)
    result: Dict[str, Dict[str, Any]] = {}

    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("clientId", "") or "").strip()
            if not cid:
                continue
            ud = item.get("userData", {})
            result[cid] = ud if isinstance(ud, dict) else {}
        return result

    if isinstance(raw, dict):
        # legacy shape: {clientId: userData}
        for cid, ud in raw.items():
            cid_s = str(cid or "").strip()
            if not cid_s:
                continue
            result[cid_s] = ud if isinstance(ud, dict) else {}

    return result


def normalize_server_name(server: Dict[str, Any], server_id: int) -> str:
    return str(server.get("name") or server.get("host") or f"server-{server_id}")


def sync_for_server_protocol(
    data: Dict[str, Any],
    server_id: int,
    protocol: str,
    direction: str,
    should_apply: bool,
) -> Tuple[List[Change], bool, bool]:
    """
    Returns (changes, remote_changed, local_changed).
    """
    servers = data.get("servers", [])
    if server_id < 0 or server_id >= len(servers):
        return [], False, False

    server = servers[server_id]
    server_name = normalize_server_name(server, server_id)

    proto_info = (server.get("protocols") or {}).get(protocol, {})
    if not proto_info.get("installed"):
        return [], False, False

    conns = [
        c for c in data.get("user_connections", [])
        if c.get("server_id") == server_id and c.get("protocol") == protocol
    ]
    if not conns:
        return [], False, False

    ssh = SSHManager(
        host=server["host"],
        port=server.get("ssh_port", 22),
        username=server["username"],
        password=server.get("password"),
        private_key=server.get("private_key"),
    )

    changes: List[Change] = []
    remote_changed = False
    local_changed = False

    try:
        ssh.connect()
        manager = get_manager(ssh, protocol)
        table, remote_idx = get_remote_clients_table(manager, protocol)

        for conn in conns:
            client_id = str(conn.get("client_id", "") or "").strip()
            connection_id = str(conn.get("id", "") or "")
            local_created = str(conn.get("created_at", "") or "").strip()

            if not client_id:
                continue

            remote_item = remote_idx.get(client_id)
            if not remote_item:
                continue

            user_data = remote_item.setdefault("userData", {})
            remote_created = str(user_data.get("creationDate", "") or "").strip()

            local_dt = parse_dt(local_created)
            remote_dt = parse_dt(remote_created)

            # We only sync valid date values.
            if direction == "data-to-remote":
                if not local_dt:
                    continue
                if remote_dt and local_dt == remote_dt:
                    continue

                if remote_created != local_created:
                    changes.append(Change(
                        server_id=server_id,
                        server_name=server_name,
                        protocol=protocol,
                        client_id=client_id,
                        connection_id=connection_id,
                        old_value=remote_created,
                        new_value=local_created,
                    ))
                    if should_apply:
                        user_data["creationDate"] = local_created
                        remote_changed = True

            else:  # remote-to-data
                if not remote_dt:
                    continue
                if local_dt and local_dt == remote_dt:
                    continue

                if local_created != remote_created:
                    changes.append(Change(
                        server_id=server_id,
                        server_name=server_name,
                        protocol=protocol,
                        client_id=client_id,
                        connection_id=connection_id,
                        old_value=local_created,
                        new_value=remote_created,
                    ))
                    if should_apply:
                        conn["created_at"] = remote_created
                        local_changed = True

        if should_apply and remote_changed:
            save_remote_clients_table(manager, protocol, table)

    finally:
        try:
            ssh.disconnect()
        except Exception:
            pass

    return changes, remote_changed, local_changed


def import_backup_to_remote(
    data: Dict[str, Any],
    server_id: int,
    protocol: str,
    backup_idx: Dict[str, Dict[str, Any]],
    should_apply: bool,
) -> Tuple[List[Change], bool]:
    servers = data.get("servers", [])
    if server_id < 0 or server_id >= len(servers):
        return [], False

    server = servers[server_id]
    server_name = normalize_server_name(server, server_id)
    proto_info = (server.get("protocols") or {}).get(protocol, {})
    if not proto_info.get("installed"):
        return [], False

    ssh = SSHManager(
        host=server["host"],
        port=server.get("ssh_port", 22),
        username=server["username"],
        password=server.get("password"),
        private_key=server.get("private_key"),
    )

    changes: List[Change] = []
    remote_changed = False

    try:
        ssh.connect()
        manager = get_manager(ssh, protocol)
        table, remote_idx = get_remote_clients_table(manager, protocol)

        for client_id, remote_item in remote_idx.items():
            backup_ud = backup_idx.get(client_id)
            if not backup_ud:
                continue

            backup_created = str(backup_ud.get("creationDate", "") or "").strip()
            if not parse_dt(backup_created):
                continue

            user_data = remote_item.setdefault("userData", {})
            remote_created = str(user_data.get("creationDate", "") or "").strip()

            if remote_created == backup_created:
                continue

            changes.append(
                Change(
                    server_id=server_id,
                    server_name=server_name,
                    protocol=protocol,
                    client_id=client_id,
                    connection_id="",
                    old_value=remote_created,
                    new_value=backup_created,
                )
            )

            if should_apply:
                user_data["creationDate"] = backup_created
                remote_changed = True

        if should_apply and remote_changed:
            save_remote_clients_table(manager, protocol, table)

    finally:
        try:
            ssh.disconnect()
        except Exception:
            pass

    return changes, remote_changed


def parse_protocols(value: str) -> List[str]:
    items = [x.strip() for x in value.split(",") if x.strip()]
    bad = [p for p in items if p not in SUPPORTED_PROTOCOLS]
    if bad:
        raise argparse.ArgumentTypeError(
            f"Unsupported protocol(s): {', '.join(bad)}. Supported: {', '.join(sorted(SUPPORTED_PROTOCOLS))}"
        )
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync connection creation dates between data.json and remote clientsTable")
    parser.add_argument("--panel-data", default="./data.json", help="Path to panel data.json")
    parser.add_argument(
        "--direction",
        choices=["data-to-remote", "remote-to-data"],
        default="data-to-remote",
        help="Sync direction (default: data-to-remote)",
    )
    parser.add_argument(
        "--protocols",
        type=parse_protocols,
        default=["awg", "awg2", "awg_legacy", "xray"],
        help="Comma-separated protocols to process",
    )
    parser.add_argument("--server-id", type=int, default=None, help="Only process a single server_id")
    parser.add_argument(
        "--backup-clients-table",
        default="",
        help="Path to old backup clientsTable to import creationDate into selected remote server",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show mismatches without changing anything")
    parser.add_argument("--apply", action="store_true", help="Apply changes")

    args = parser.parse_args()

    if not args.dry_run and not args.apply:
        print("No mode selected. Use --dry-run to preview or --apply to write changes.", file=sys.stderr)
        return 2

    data_path = Path(args.panel_data).resolve()
    if not data_path.exists():
        print(f"data.json not found: {data_path}", file=sys.stderr)
        return 2

    data = load_json(data_path)
    servers = data.get("servers", [])

    backup_mode = bool((args.backup_clients_table or "").strip())
    backup_idx: Dict[str, Dict[str, Any]] = {}
    if backup_mode:
        if args.server_id is None:
            print("In backup mode, --server-id is required.", file=sys.stderr)
            return 2
        if len(args.protocols) != 1:
            print("In backup mode, pass exactly one protocol in --protocols.", file=sys.stderr)
            return 2
        backup_path = Path(args.backup_clients_table).resolve()
        if not backup_path.exists():
            print(f"Backup clientsTable not found: {backup_path}", file=sys.stderr)
            return 2
        backup_idx = load_backup_clients_table(backup_path)
        print(f"Backup mode: loaded {len(backup_idx)} entries from {backup_path}")

    server_ids = [args.server_id] if args.server_id is not None else list(range(len(servers)))

    all_changes: List[Change] = []
    any_remote_changed = False
    any_local_changed = False

    for sid in server_ids:
        if sid < 0 or sid >= len(servers):
            print(f"SKIP server_id={sid}: out of range")
            continue

        server = servers[sid]
        server_name = normalize_server_name(server, sid)
        print(f"\n=== Server {sid}: {server_name} ===")

        for proto in args.protocols:
            try:
                if backup_mode:
                    changes, remote_changed = import_backup_to_remote(
                        data=data,
                        server_id=sid,
                        protocol=proto,
                        backup_idx=backup_idx,
                        should_apply=args.apply,
                    )
                    local_changed = False
                else:
                    changes, remote_changed, local_changed = sync_for_server_protocol(
                        data=data,
                        server_id=sid,
                        protocol=proto,
                        direction=args.direction,
                        should_apply=args.apply,
                    )
            except Exception as e:
                print(f"ERROR {proto}: {e}")
                continue

            if not changes:
                print(f"{proto}: no mismatches")
                continue

            print(f"{proto}: mismatches={len(changes)}")
            for c in changes:
                print(
                    f"  - conn={c.connection_id} client={c.client_id} old='{c.old_value}' -> new='{c.new_value}'"
                )

            all_changes.extend(changes)
            any_remote_changed = any_remote_changed or remote_changed
            any_local_changed = any_local_changed or local_changed

    print("\n=== Summary ===")
    if backup_mode:
        print("Direction: backup-to-remote")
    else:
        print(f"Direction: {args.direction}")
    print(f"Total mismatches: {len(all_changes)}")

    if args.dry_run:
        print("Dry-run complete. No changes were written.")
        return 0

    if args.apply:
        if not backup_mode and args.direction == "remote-to-data" and any_local_changed:
            save_json(data_path, data)
            print(f"Updated local data.json: {data_path}")
        elif not backup_mode and args.direction == "remote-to-data":
            print("No local changes to write.")

        if backup_mode:
            if any_remote_changed:
                print("Updated remote clientsTable entries from backup.")
            else:
                print("No remote changes were required from backup.")
        elif args.direction == "data-to-remote":
            if any_remote_changed:
                print("Updated remote clientsTable entries.")
            else:
                print("No remote changes were required.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
