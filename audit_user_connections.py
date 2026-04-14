#!/usr/bin/env python3
"""
Read-only audit of panel user_connections against remote AWG servers.

What it does:
- reads local data.json
- for each (server_id, protocol) group in user_connections
- fetches remote clients via AWGManager.get_clients(protocol)
- reports client_id entries present in panel but missing on server

It never modifies remote servers or data.json.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from ssh_manager import SSHManager
from awg_manager import AWGManager


SUPPORTED_PROTOCOLS = {"awg", "awg2", "awg_legacy"}


def parse_protocols(raw: str) -> set[str]:
	return {p.strip() for p in (raw or "").split(",") if p.strip()}


def load_json(path: Path) -> dict:
	return json.loads(path.read_text(encoding="utf-8"))


def make_ssh(server: dict) -> SSHManager:
	return SSHManager(
		host=server.get("host", ""),
		port=server.get("ssh_port", 22),
		username=server.get("username", "root"),
		password=server.get("password", ""),
		private_key=server.get("private_key", ""),
	)


def fetch_remote_client_ids(server: dict, protocol: str) -> set[str]:
	ssh = make_ssh(server)
	try:
		ssh.connect()
		manager = AWGManager(ssh)
		clients = manager.get_clients(protocol)
		return {
			str(item.get("clientId", "")).strip()
			for item in clients
			if str(item.get("clientId", "")).strip()
		}
	finally:
		try:
			ssh.disconnect()
		except Exception:
			pass


def main() -> None:
	parser = argparse.ArgumentParser(
		description="Audit user_connections in data.json against remote AWG clients"
	)
	parser.add_argument("--panel-data", default="./data.json", help="Path to panel data.json")
	parser.add_argument(
		"--protocols",
		default="awg",
		help="Comma-separated protocols to audit (default: awg)",
	)
	parser.add_argument(
		"--include-remote-orphans",
		action="store_true",
		help="Also print remote client IDs that are not linked in panel",
	)
	parser.add_argument(
		"--output-json",
		default="",
		help="Optional path to write detailed JSON report",
	)
	args = parser.parse_args()

	panel_data_path = Path(args.panel_data).expanduser().resolve()
	if not panel_data_path.exists():
		raise RuntimeError(f"panel data file not found: {panel_data_path}")

	protocols = parse_protocols(args.protocols)
	if not protocols:
		raise RuntimeError("empty protocols list")

	unsupported = protocols - SUPPORTED_PROTOCOLS
	if unsupported:
		raise RuntimeError(
			"Unsupported protocols: "
			+ ", ".join(sorted(unsupported))
			+ ". Supported: "
			+ ", ".join(sorted(SUPPORTED_PROTOCOLS))
		)

	data = load_json(panel_data_path)
	servers = data.get("servers", [])
	users_map = {str(u.get("id")): str(u.get("username", "")) for u in data.get("users", [])}
	user_connections = data.get("user_connections", [])

	grouped: dict[tuple[int, str], list[dict]] = defaultdict(list)
	for conn in user_connections:
		proto = str(conn.get("protocol", ""))
		sid = conn.get("server_id")
		if proto in protocols and isinstance(sid, int):
			grouped[(sid, proto)].append(conn)

	report = {
		"panel_data": str(panel_data_path),
		"protocols": sorted(protocols),
		"summary": {
			"groups": 0,
			"links_total": 0,
			"links_present_remote": 0,
			"links_missing_remote": 0,
			"groups_with_errors": 0,
			"invalid_server_links": 0,
		},
		"groups": [],
	}

	for (server_id, protocol), entries in sorted(grouped.items(), key=lambda x: (x[0][0], x[0][1])):
		report["summary"]["groups"] += 1
		report["summary"]["links_total"] += len(entries)

		group_info = {
			"server_id": server_id,
			"server_name": "",
			"protocol": protocol,
			"links_total": len(entries),
			"missing": [],
			"error": "",
		}

		if server_id < 0 or server_id >= len(servers):
			group_info["error"] = f"invalid server_id {server_id}"
			report["summary"]["groups_with_errors"] += 1
			report["summary"]["invalid_server_links"] += len(entries)
			report["groups"].append(group_info)
			continue

		server = servers[server_id]
		group_info["server_name"] = server.get("name") or server.get("host") or f"server#{server_id}"

		expected_ids = {
			str(c.get("client_id", "")).strip()
			for c in entries
			if str(c.get("client_id", "")).strip()
		}

		try:
			remote_ids = fetch_remote_client_ids(server, protocol)
		except Exception as e:
			group_info["error"] = str(e)
			report["summary"]["groups_with_errors"] += 1
			report["groups"].append(group_info)
			continue

		missing_ids = expected_ids - remote_ids
		present_count = len(expected_ids & remote_ids)

		report["summary"]["links_present_remote"] += present_count
		report["summary"]["links_missing_remote"] += len(missing_ids)

		if missing_ids:
			for conn in entries:
				cid = str(conn.get("client_id", "")).strip()
				if cid in missing_ids:
					uid = str(conn.get("user_id", ""))
					group_info["missing"].append(
						{
							"connection_id": conn.get("id"),
							"user_id": uid,
							"username": users_map.get(uid, ""),
							"name": conn.get("name"),
							"client_id": cid,
						}
					)

		if args.include_remote_orphans:
			group_info["remote_orphans"] = sorted(remote_ids - expected_ids)

		report["groups"].append(group_info)

	print("=== Audit summary ===")
	print(f"Panel file: {report['panel_data']}")
	print(f"Protocols: {', '.join(report['protocols'])}")
	print(f"Groups: {report['summary']['groups']}")
	print(f"Links total: {report['summary']['links_total']}")
	print(f"Present on server: {report['summary']['links_present_remote']}")
	print(f"Missing on server: {report['summary']['links_missing_remote']}")
	print(f"Groups with errors: {report['summary']['groups_with_errors']}")

	for g in report["groups"]:
		if g.get("error"):
			print(f"[ERROR] server={g['server_id']} protocol={g['protocol']} -> {g['error']}")
			continue
		miss = len(g.get("missing", []))
		print(f"[OK] server={g['server_name']} protocol={g['protocol']} missing={miss}/{g['links_total']}")
		for m in g.get("missing", []):
			print(
				"  - "
				f"user={m.get('username') or m.get('user_id')} "
				f"name={m.get('name')} "
				f"client_id={m.get('client_id')}"
			)

	if args.output_json:
		out_path = Path(args.output_json).expanduser().resolve()
		out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
		print(f"Detailed report saved: {out_path}")


if __name__ == "__main__":
	main()

