#!/usr/bin/env python3
"""
OpenFlux healthcheck / garbage collector.

Reconciles per-user OpenFlux exit containers on every managed server against the
panel's user_connections, frees resources, and notifies affected users.

Default is a DRY RUN — reports only, sends NO notifications, changes nothing.
Pass --apply to act.

--apply:
  • removes orphan containers   (container on server, no connection record, older
                                 than the grace period)                 -> frees RAM
  • removes stale records        (connection record, but no container)  -> cleans data.json
  • notifies users               of down (crashed) tunnels and removed records
--revalidate (opt-in, disruptive): for each live tunnel, STOP the container, re-check
                                 the doc still authorizes, then restart it (valid) or
                                 remove it + record + notify (invalid). Stopping first
                                 avoids opening a second session on the same doc.

Safety:
  • aborts a server if docker is unresponsive (never mass-purges on a transient error)
  • re-reads data.json fresh before acting (a connection created mid-run is not purged)
  • honours a grace period so freshly-created containers are never treated as orphans
  • writes data.json atomically under a cross-process lock shared with the panel

Cron (safe), every 30 min:
    */30 * * * * cd /opt/amnezia-web-panel && python3 openflux_healthcheck.py --apply >> /var/log/openflux_gc.log 2>&1
"""

import argparse
import contextlib
import datetime
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import fcntl
except Exception:
    fcntl = None

from managers.ssh_manager import SSHManager
from managers.openflux_manager import OpenFluxManager

ORPHAN_GRACE_SEC = 300  # don't remove containers younger than this (avoids TOCTOU)


def _base(p):
    return str(p or "").split("__")[0]


def load_data(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


@contextlib.contextmanager
def _flock(path):
    """Exclusive cross-process lock on the same lockfile app.py uses."""
    if fcntl is None:
        yield
        return
    lk = open(path + ".lock", "a+")
    try:
        fcntl.flock(lk, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lk, fcntl.LOCK_UN)
        finally:
            lk.close()


def atomic_write(path, data):
    tmp = path + ".tmp"
    Path(tmp).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def notify(token, chat_id, text):
    if not token or not chat_id:
        return
    try:
        body = urllib.parse.urlencode({"chat_id": str(chat_id), "text": text}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=body, timeout=15)
    except Exception as e:
        print(f"    ! notify {chat_id} failed: {e}")


def docker_ok(ssh):
    out, _, _ = ssh.run_sudo_command("docker ps -q >/dev/null 2>&1 && echo ok || echo fail")
    return "ok" in out


def container_age_sec(ssh, name):
    out, _, _ = ssh.run_sudo_command("docker inspect -f '{{.Created}}' " + name + " 2>/dev/null")
    ts = out.strip()
    if not ts:
        return None
    try:
        clean = ts.split(".")[0].replace("Z", "").strip()
        dt = datetime.datetime.fromisoformat(clean)
        return max(0.0, (datetime.datetime.utcnow() - dt).total_seconds())
    except Exception:
        return None


DOWN_MSG = (
    "⚠️ Ваш аварийный туннель OpenFlux не работает. "
    "Проверьте, что документ ещё публичный (доступ по ссылке — редактирование), "
    "или создайте новый профиль в боте."
)
GONE_MSG = (
    "⚠️ Ваш аварийный туннель OpenFlux был удалён (документ недоступен или закрыт доступ). "
    "Создайте новый профиль в боте, когда понадобится."
)


def main():
    ap = argparse.ArgumentParser(description="OpenFlux healthcheck / GC")
    ap.add_argument("--data-file", default=str(Path(__file__).resolve().parent / "data.json"))
    ap.add_argument("--apply", action="store_true", help="actually remove orphans/stale records + notify (default: dry run)")
    ap.add_argument("--revalidate", action="store_true", help="re-check each doc (stops the container first; disruptive)")
    ap.add_argument("--quiet-notify", action="store_true", help="never send Telegram notifications")
    args = ap.parse_args()

    data = load_data(args.data_file)
    # Notifications only ever fire on a real --apply run (never on a dry run).
    token = ""
    if args.apply and not args.quiet_notify:
        token = data.get("settings", {}).get("telegram", {}).get("token", "")

    servers = data.get("servers", [])
    of_conns = [c for c in data.get("user_connections", []) if _base(c.get("protocol", "")) == "openflux"]
    if not of_conns:
        print("No OpenFlux connections tracked — nothing to do.")
        return

    of_by_server = {}
    for c in of_conns:
        of_by_server.setdefault(c.get("server_id"), set()).add(str(c.get("client_id")))

    remove_conn_ids = set()
    pending_notifs = []  # (chat_id, message)
    users = {u["id"]: u for u in data.get("users", [])}

    def tgid_for(conn):
        return (users.get(conn.get("user_id")) or {}).get("telegramId")

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"=== OpenFlux healthcheck ({mode}) — {len(of_conns)} connection(s), {len(of_by_server)} server(s) ===")

    for sid, snapshot_active in of_by_server.items():
        if not isinstance(sid, int) or sid < 0 or sid >= len(servers):
            print(f"[server {sid}] not found -> {len(snapshot_active)} stale record(s)")
            for c in of_conns:
                if c.get("server_id") == sid:
                    remove_conn_ids.add(c.get("id"))
                    pending_notifs.append((tgid_for(c), GONE_MSG))
            continue

        server = servers[sid]
        try:
            ssh = SSHManager.for_server(server, data)
            ssh.connect()
        except Exception as e:
            print(f"[server {sid} {server.get('name', '')}] ssh failed: {e} — skipping")
            continue
        try:
            mgr = OpenFluxManager(ssh)
            if not mgr.check_protocol_installed():
                print(f"[server {sid} {server.get('name', '')}] OpenFlux not installed — skipping")
                continue
            if not docker_ok(ssh):
                print(f"[server {sid} {server.get('name', '')}] docker not responsive — skipping (won't purge)")
                continue

            report = mgr.reconcile(snapshot_active, apply=False)  # report only; we drive removals
            seen = set(report["seen"])

            # Re-read FRESH so a connection created during the run is not purged.
            fresh = load_data(args.data_file)
            fresh_on_srv = [c for c in fresh.get("user_connections", [])
                            if _base(c.get("protocol", "")) == "openflux" and c.get("server_id") == sid]
            fresh_active = {str(c.get("client_id")) for c in fresh_on_srv}

            print(f"[server {sid} {server.get('name', '')}] "
                  f"orphan_candidates={report['removed_orphans']} "
                  f"down={[d['client_id'] for d in report['down']]} running={len(report['running'])}")

            # orphan containers (no fresh record, past grace) -> remove
            for cid in report["removed_orphans"]:
                if cid in fresh_active:
                    continue  # created mid-run
                name = f"{mgr.CONTAINER_PREFIX}-{cid}"
                age = container_age_sec(ssh, name)
                if age is not None and age < ORPHAN_GRACE_SEC:
                    print(f"    orphan {cid}: too young ({int(age)}s) — skip")
                    continue
                print(f"    orphan {cid}: {'removing' if args.apply else 'would remove'}")
                if args.apply:
                    ssh.run_sudo_command(f"docker rm -f {name} || true")

            # down (crashed) containers -> notify owner
            for d in report["down"]:
                c = next((x for x in fresh_on_srv if str(x.get("client_id")) == d["client_id"]), None)
                if c:
                    print(f"    down {d['client_id']}: notify owner")
                    pending_notifs.append((tgid_for(c), DOWN_MSG))

            # stale records (record present, container gone) -> drop record + notify
            for c in fresh_on_srv:
                if str(c.get("client_id")) not in seen:
                    print(f"    stale record {c.get('id')} (no container) -> {'remove' if args.apply else 'would remove'}")
                    remove_conn_ids.add(c.get("id"))
                    pending_notifs.append((tgid_for(c), GONE_MSG))

            # optional deep check: stop -> validate -> restart|remove (no 2nd session)
            if args.revalidate:
                for c in fresh_on_srv:
                    cid = str(c.get("client_id"))
                    if cid not in seen:
                        continue
                    name = f"{mgr.CONTAINER_PREFIX}-{cid}"
                    if args.apply:
                        ssh.run_sudo_command(f"docker stop {name} || true")
                    ok, reason = mgr.validate_doc(c.get("doc_url", ""), c.get("transport"))
                    if ok:
                        print(f"    revalidate {cid}: OK")
                        if args.apply:
                            ssh.run_sudo_command(f"docker start {name} || true")
                    else:
                        print(f"    revalidate {cid}: doc invalid ({reason}) -> {'remove' if args.apply else 'would remove'}")
                        if args.apply:
                            ssh.run_sudo_command(f"docker rm -f {name} || true")
                        remove_conn_ids.add(c.get("id"))
                        pending_notifs.append((tgid_for(c), GONE_MSG))
        finally:
            try:
                ssh.disconnect()
            except Exception:
                pass

    # notifications (token is empty unless --apply, so dry runs never send)
    for chat_id, msg in pending_notifs:
        notify(token, chat_id, msg)

    if remove_conn_ids:
        print(f"\n{len(remove_conn_ids)} stale record(s) to remove")
        if args.apply:
            with _flock(args.data_file):
                fresh = load_data(args.data_file)  # re-read under lock; remove only our target ids
                fresh["user_connections"] = [c for c in fresh.get("user_connections", []) if c.get("id") not in remove_conn_ids]
                atomic_write(args.data_file, fresh)
            print("data.json updated.")
        else:
            print("(dry run — pass --apply to remove them)")
    else:
        print("\nNothing to clean.")


if __name__ == "__main__":
    sys.exit(main())
