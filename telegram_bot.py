"""
Telegram bot for Amnezia Web Panel.
Uses raw Telegram Bot API via httpx — no library version conflicts.
Runs as a background asyncio task alongside the FastAPI app.
"""
import asyncio
import logging
import html
from typing import Optional, Callable
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------- #
#  Global state
# ----------------------------------------------------------------------- #
_bot_task: Optional[asyncio.Task] = None
_pending_profile_create: dict = {}


def is_running() -> bool:
    return _bot_task is not None and not _bot_task.done()


def launch_bot(token: str, load_data_fn: Callable, save_data_fn: Callable, generate_vpn_link_fn: Callable):
    global _bot_task
    _bot_task = asyncio.create_task(
        _run_bot(token, load_data_fn, save_data_fn, generate_vpn_link_fn),
        name="telegram_bot",
    )
    return _bot_task


async def stop_bot():
    global _bot_task
    if _bot_task and not _bot_task.done():
        _bot_task.cancel()
        try:
            await _bot_task
        except asyncio.CancelledError:
            pass
        _bot_task = None
        logger.info("Telegram bot stopped.")


# ----------------------------------------------------------------------- #
#  Low-level Telegram API helpers
# ----------------------------------------------------------------------- #
class TelegramAPI:
    def __init__(self, token: str, client: httpx.AsyncClient):
        self.base = f"https://api.telegram.org/bot{token}"
        self.client = client

    async def call(self, method: str, **params) -> dict:
        r = await self.client.post(f"{self.base}/{method}", json=params, timeout=30)
        return r.json()

    async def get_updates(self, offset: int = 0, timeout: int = 25) -> list:
        r = await self.client.post(
            f"{self.base}/getUpdates",
            json={"offset": offset, "timeout": timeout, "allowed_updates": ["message", "callback_query"]},
            timeout=timeout + 10,
        )
        data = r.json()
        if data.get("ok"):
            return data["result"]
        return []

    async def send_message(self, chat_id, text: str, reply_markup=None, parse_mode="HTML") -> dict:
        import json
        params = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
        if reply_markup:
            params["reply_markup"] = json.dumps(reply_markup)
        return (await self.call("sendMessage", **params))

    async def edit_message(self, chat_id, message_id, text: str, reply_markup=None, parse_mode="HTML"):
        import json
        params = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": parse_mode}
        if reply_markup:
            params["reply_markup"] = json.dumps(reply_markup)
        await self.call("editMessageText", **params)

    async def answer_callback(self, callback_query_id: str, text: str = ""):
        await self.call("answerCallbackQuery", callback_query_id=callback_query_id, text=text)

    async def send_document(self, chat_id, filename: str, content: bytes, caption: str = "", parse_mode: str = "HTML"):
        files = {"document": (filename, content, "text/plain")}
        data = {"chat_id": str(chat_id), "caption": caption, "parse_mode": parse_mode}
        r = await self.client.post(f"{self.base}/sendDocument", data=data, files=files, timeout=30)
        return r.json()


# ----------------------------------------------------------------------- #
#  Helpers
# ----------------------------------------------------------------------- #
def _find_user(load_data_fn: Callable, tg_id: str):
    data = load_data_fn()
    tg_id_clean = str(tg_id).lstrip("@")
    for u in data.get("users", []):
        stored = str(u.get("telegramId", "") or "").lstrip("@")
        if stored and stored == tg_id_clean:
            return u
    return None


def _parse_dt(value: str):
    v = str(value or "").strip()
    if not v:
        return datetime.min

    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(v, fmt)
        except Exception:
            continue

    return datetime.min


def _sort_connections_newest_first(conns: list) -> list:
    return sorted(conns, key=lambda c: _parse_dt(c.get("created_at", "")), reverse=True)


def _build_connections_keyboard(conns: list, data: dict) -> dict:
    """Build inline keyboard where each button = one connection."""
    rows = []
    servers = data.get("servers", [])
    for c in conns:
        sid = c.get("server_id", 0)
        server_name = "Unknown"
        if sid < len(servers):
            srv = servers[sid]
            server_name = srv.get("name") or srv.get("host", "Unknown")[:20]
        proto = c.get("protocol", "").upper()
        name = c.get("name", "Connection")
        label = f"🔐 {name} · {proto} · {server_name}"
        # callback_data must be ≤ 64 bytes — use short prefix
        rows.append([{"text": label, "callback_data": f"cfg:{c['id']}"}])
    rows.append([{"text": "➕ Создать профиль", "callback_data": "new:start"}])
    rows.append([{"text": "🗑 Удалить профиль", "callback_data": "del:start"}])
    rows.append([{"text": "🔄 Обновить список", "callback_data": "refresh"}])
    return {"inline_keyboard": rows}


def _build_servers_keyboard(data: dict) -> dict:
    rows = []
    for sid, srv in enumerate(data.get("servers", [])):
        name = srv.get("name") or srv.get("host", "Unknown")
        emoji = srv.get("emoji", "🖥")
        rows.append([{"text": f"{emoji} {name}", "callback_data": f"new:srv:{sid}"}])
    rows.append([{"text": "⬅️ Назад", "callback_data": "refresh"}])
    return {"inline_keyboard": rows}


def _build_protocols_keyboard(server: dict, sid: int) -> dict:
    supported = ["awg", "awg2", "awg_legacy", "xray", "telemt"]
    rows = []
    for proto in supported:
        if server.get("protocols", {}).get(proto, {}).get("installed"):
            rows.append([{"text": f"{proto.upper()}", "callback_data": f"new:proto:{sid}:{proto}"}])
    rows.append([{"text": "⬅️ К серверам", "callback_data": "new:start"}])
    rows.append([{"text": "↩️ К списку", "callback_data": "refresh"}])
    return {"inline_keyboard": rows}


def _build_delete_keyboard(conns: list) -> dict:
    rows = []
    for c in conns:
        proto = c.get("protocol", "").upper()
        name = c.get("name", "Connection")
        rows.append([{"text": f"❌ {name} · {proto}", "callback_data": f"del:{c['id']}"}])
    rows.append([{"text": "⬅️ Назад", "callback_data": "refresh"}])
    return {"inline_keyboard": rows}


async def _send_profile_document(api: TelegramAPI, chat_id: int, conn_name: str, vpn_link: str, config: str):
    safe_name = html.escape(conn_name or "Connection")
    safe_link = html.escape(vpn_link or "")
    caption = (
        f"<b>{safe_name}</b>\n"
        f"<blockquote><code>{safe_link}</code></blockquote>"
    )
    filename = f"{(conn_name or 'connection').replace(' ', '_')}.conf"
    await api.send_document(
        chat_id,
        filename=filename,
        content=(config or "").encode("utf-8"),
        caption=caption,
        parse_mode="HTML",
    )


async def _create_connection_for_user(
    panel_user: dict,
    server_id: int,
    protocol: str,
    name: str,
    load_data_fn: Callable,
    save_data_fn: Callable,
    generate_vpn_link_fn: Callable,
):
    import uuid
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from ssh_manager import SSHManager
    from awg_manager import AWGManager
    from xray_manager import XrayManager

    data = load_data_fn()
    my_conns = [c for c in data.get("user_connections", []) if c.get("user_id") == panel_user["id"]]
    if panel_user.get("role") == "user" and len(my_conns) >= 10:
        raise RuntimeError("Maximum 10 connections per user reached")

    if server_id < 0 or server_id >= len(data.get("servers", [])):
        raise RuntimeError("Server not found")

    protocol = (protocol or "awg").strip()
    supported_protocols = {"awg", "awg2", "awg_legacy", "xray", "telemt"}
    if protocol not in supported_protocols:
        raise RuntimeError(f"Unsupported protocol: {protocol}")

    server = data["servers"][server_id]
    proto_info = server.get("protocols", {}).get(protocol, {})
    if not proto_info.get("installed"):
        raise RuntimeError(f"Protocol {protocol} is not installed on selected server")

    port_default = "443" if protocol == "telemt" else "55424"
    port = proto_info.get("port", port_default)
    conn_name = (name or "VPN Connection").strip() or "VPN Connection"

    ssh = SSHManager(
        server["host"],
        server.get("ssh_port", 22),
        server["username"],
        server.get("password", ""),
        server.get("private_key", ""),
    )
    ssh.connect()
    try:
        if protocol == "xray":
            manager = XrayManager(ssh)
        else:
            manager = AWGManager(ssh)
        result = manager.add_client(protocol, conn_name, server["host"], port)
    finally:
        ssh.disconnect()

    if not result.get("client_id"):
        raise RuntimeError("Failed to create connection on server")

    new_conn = {
        "id": str(uuid.uuid4()),
        "user_id": panel_user["id"],
        "server_id": server_id,
        "protocol": protocol,
        "client_id": result["client_id"],
        "name": conn_name,
        "created_at": datetime.now().isoformat(),
    }
    data.setdefault("user_connections", []).append(new_conn)
    save_data_fn(data)

    config = result.get("config", "")
    vpn_link = result.get("vpn_link") or (generate_vpn_link_fn(config) if config else "")
    return new_conn, config, vpn_link


async def _remove_connection_for_user(
    panel_user: dict,
    connection_id: str,
    load_data_fn: Callable,
    save_data_fn: Callable,
):
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from ssh_manager import SSHManager
    from awg_manager import AWGManager
    from xray_manager import XrayManager

    data = load_data_fn()
    conn = next(
        (c for c in data.get("user_connections", []) if c.get("id") == connection_id and c.get("user_id") == panel_user["id"]),
        None,
    )
    if not conn:
        raise RuntimeError("Connection not found")

    sid = conn.get("server_id", -1)
    if sid < 0 or sid >= len(data.get("servers", [])):
        raise RuntimeError("Server not found")

    server = data["servers"][sid]
    protocol = conn.get("protocol", "awg")

    ssh = SSHManager(
        server["host"],
        server.get("ssh_port", 22),
        server["username"],
        server.get("password", ""),
        server.get("private_key", ""),
    )
    try:
        ssh.connect()
        if protocol == "xray":
            manager = XrayManager(ssh)
        else:
            manager = AWGManager(ssh)
        manager.remove_client(protocol, conn.get("client_id", ""))
    except Exception as e:
        if "not found" not in str(e).lower():
            raise
    finally:
        try:
            ssh.disconnect()
        except Exception:
            pass

    data["user_connections"] = [c for c in data.get("user_connections", []) if c.get("id") != connection_id]
    save_data_fn(data)



# ----------------------------------------------------------------------- #
#  /start handler — shows connections list immediately
# ----------------------------------------------------------------------- #
async def _handle_start(api: TelegramAPI, msg: dict, load_data_fn: Callable):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    first_name = msg["from"].get("first_name", "")

    panel_user = _find_user(load_data_fn, tg_id)

    if not panel_user:
        await api.send_message(
            chat_id,
            f"👋 Hi, <b>{first_name}</b>!\n\n"
            "Your Telegram account is not linked to any panel user.\n"
            "Please contact your administrator — they need to add your Telegram ID to your profile.\n\n"
            f"Your Telegram ID: <code>{tg_id}</code>",
        )
        return

    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c["user_id"] == panel_user["id"]]
    conns = _sort_connections_newest_first(conns)

    if not conns:
        await api.send_message(
            chat_id,
            f"👋 Hi, <b>{first_name}</b>!\n\n"
            f"You are registered as <b>{panel_user['username']}</b>.\n\n"
            "You have no connections yet. Please contact your administrator.",
        )
        return

    kb = _build_connections_keyboard(conns, data)
    await api.send_message(
        chat_id,
        f"👋 Hi, <b>{first_name}</b>!\n\n"
        f"You are registered as <b>{panel_user['username']}</b>.\n\n"
        f"<b>Your connections</b> ({len(conns)}) — tap to get config:",
        reply_markup=kb,
    )


# ----------------------------------------------------------------------- #
#  Refresh — edit existing message with updated list
# ----------------------------------------------------------------------- #
async def _handle_refresh(
    api: TelegramAPI,
    chat_id: int,
    message_id: int,
    callback_id: str,
    tg_id: str,
    load_data_fn: Callable,
    answer_callback: bool = True,
):
    if answer_callback:
        await api.answer_callback(callback_id, "Updated!")
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return
    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c["user_id"] == panel_user["id"]]
    conns = _sort_connections_newest_first(conns)
    if not conns:
        await api.edit_message(chat_id, message_id, "You have no connections.")
        return
    kb = _build_connections_keyboard(conns, data)
    await api.edit_message(
        chat_id, message_id,
        f"<b>Your connections</b> ({len(conns)}) — tap to get config:",
        reply_markup=kb,
    )


async def _handle_new_start(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, load_data_fn: Callable):
    await api.answer_callback(callback_id, "Выберите сервер")
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return
    data = load_data_fn()
    if not data.get("servers"):
        await api.edit_message(chat_id, message_id, "❌ Нет серверов для создания профиля.")
        return
    kb = _build_servers_keyboard(data)
    await api.edit_message(chat_id, message_id, "<b>Создание профиля</b>\nВыберите сервер:", reply_markup=kb)


async def _handle_new_server(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, sid: int, load_data_fn: Callable):
    await api.answer_callback(callback_id, "Выберите протокол")
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return
    data = load_data_fn()
    if sid < 0 or sid >= len(data.get("servers", [])):
        await api.edit_message(chat_id, message_id, "❌ Server not found.")
        return
    server = data["servers"][sid]
    kb = _build_protocols_keyboard(server, sid)
    await api.edit_message(chat_id, message_id, f"<b>Создание профиля</b>\nСервер: <b>{html.escape(server.get('name') or server.get('host', 'Unknown'))}</b>\nВыберите протокол:", reply_markup=kb)


async def _handle_new_protocol(
    api: TelegramAPI,
    chat_id: int,
    message_id: int,
    callback_id: str,
    tg_id: str,
    sid: int,
    protocol: str,
    load_data_fn: Callable,
    save_data_fn: Callable,
    generate_vpn_link_fn: Callable,
):
    await api.answer_callback(callback_id, "Введите имя профиля")
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return
    try:
        _pending_profile_create[tg_id] = {
            "server_id": sid,
            "protocol": protocol,
            "chat_id": chat_id,
            "message_id": message_id,
        }
        await api.edit_message(
            chat_id,
            message_id,
            "<b>Создание профиля</b>\n"
            f"Протокол: <b>{html.escape(protocol.upper())}</b>\n"
            "Отправьте название профиля одним сообщением.\n"
            "Для отмены отправьте: <code>/cancel</code>",
        )
    except Exception as e:
        logger.exception("Bot: error creating profile")
        await api.edit_message(chat_id, message_id, f"❌ Error: {html.escape(str(e))}")


async def _handle_profile_name_input(
    api: TelegramAPI,
    msg: dict,
    tg_id: str,
    state: dict,
    load_data_fn: Callable,
    save_data_fn: Callable,
    generate_vpn_link_fn: Callable,
):
    chat_id = msg["chat"]["id"]
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        _pending_profile_create.pop(tg_id, None)
        await api.send_message(chat_id, "❌ Access denied.")
        return

    requested_name = (msg.get("text") or "").strip()
    if not requested_name:
        await api.send_message(chat_id, "Введите непустое название профиля.")
        return

    try:
        conn, config, vpn_link = await _create_connection_for_user(
            panel_user=panel_user,
            server_id=state["server_id"],
            protocol=state["protocol"],
            name=requested_name,
            load_data_fn=load_data_fn,
            save_data_fn=save_data_fn,
            generate_vpn_link_fn=generate_vpn_link_fn,
        )
        await _send_profile_document(api, chat_id, conn.get("name", "Connection"), vpn_link, config)
        await _handle_refresh(
            api,
            state.get("chat_id", chat_id),
            state.get("message_id", msg.get("message_id", 0)),
            "",
            tg_id,
            load_data_fn,
            answer_callback=False,
        )
    except Exception as e:
        logger.exception("Bot: error creating profile from name input")
        await api.send_message(chat_id, f"❌ Error: {html.escape(str(e))}")
    finally:
        _pending_profile_create.pop(tg_id, None)


async def _handle_delete_start(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, load_data_fn: Callable):
    await api.answer_callback(callback_id, "Выберите профиль")
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return
    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == panel_user["id"]]
    conns = _sort_connections_newest_first(conns)
    if not conns:
        await api.edit_message(chat_id, message_id, "У вас нет профилей для удаления.")
        return
    kb = _build_delete_keyboard(conns)
    await api.edit_message(chat_id, message_id, "<b>Удаление профиля</b>\nВыберите профиль:", reply_markup=kb)


async def _handle_delete_connection(
    api: TelegramAPI,
    chat_id: int,
    message_id: int,
    callback_id: str,
    tg_id: str,
    connection_id: str,
    load_data_fn: Callable,
    save_data_fn: Callable,
):
    await api.answer_callback(callback_id, "Удаляю профиль...")
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return
    try:
        await _remove_connection_for_user(panel_user, connection_id, load_data_fn, save_data_fn)
        await _handle_refresh(api, chat_id, message_id, callback_id, tg_id, load_data_fn, answer_callback=False)
    except Exception as e:
        logger.exception("Bot: error deleting profile")
        await api.edit_message(chat_id, message_id, f"❌ Error: {html.escape(str(e))}")


# ----------------------------------------------------------------------- #
#  Get config — send multiple messages with different formats
# ----------------------------------------------------------------------- #
async def _handle_get_config(
    api: TelegramAPI,
    chat_id: int,
    message_id: int,
    callback_id: str,
    conn_id: str,
    tg_id: str,
    load_data_fn: Callable,
    generate_vpn_link_fn: Callable,
):
    await api.answer_callback(callback_id, "Готовлю конфиг...")

    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.send_message(chat_id, "❌ Access denied.")
        return

    data = load_data_fn()
    conn = next(
        (c for c in data.get("user_connections", [])
         if c["id"] == conn_id and c["user_id"] == panel_user["id"]),
        None,
    )
    if not conn:
        await api.send_message(chat_id, "❌ Connection not found.")
        return

    sid = conn["server_id"]
    servers = data.get("servers", [])
    if sid >= len(servers):
        await api.send_message(chat_id, "❌ Server not found.")
        return

    server = servers[sid]
    proto = conn.get("protocol", "awg")
    conn_name = conn.get("name", "Connection")

    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from ssh_manager import SSHManager
        from awg_manager import AWGManager
        from xray_manager import XrayManager

        ssh = SSHManager(
            server["host"],
            server.get("ssh_port", 22),
            server["username"],
            server.get("password", ""),
            server.get("private_key", ""),
        )

        proto_info = server.get("protocols", {}).get(proto, {})
        port = proto_info.get("port", "55424")

        def _get_cfg():
            ssh.connect()
            try:
                if proto == "xray":
                    mgr = XrayManager(ssh)
                else:
                    mgr = AWGManager(ssh)
                return mgr.get_client_config(proto, conn["client_id"], server["host"], port)
            except RuntimeError as e:
                # Imported legacy profiles may not have private key on server.
                # In that case serve locally stored imported config.
                if "private key not stored" in str(e).lower():
                    imported_cfg = conn.get("imported_config", "")
                    if imported_cfg:
                        return imported_cfg
                raise
            finally:
                ssh.disconnect()

        config = await asyncio.to_thread(_get_cfg)

        if not config:
            await api.send_message(chat_id, "❌ Failed to retrieve configuration.")
            return

        vpn_link = generate_vpn_link_fn(config) if config else ""

        await _send_profile_document(api, chat_id, conn_name, vpn_link, config)

    except Exception as e:
        logger.exception("Bot: error getting config")
        await api.send_message(chat_id, f"❌ Error: {html.escape(str(e))}")


# ----------------------------------------------------------------------- #
#  Main polling loop
# ----------------------------------------------------------------------- #
async def _run_bot(token: str, load_data_fn: Callable, save_data_fn: Callable, generate_vpn_link_fn: Callable):
    offset = 0
    logger.info("Telegram bot started (raw httpx polling).")

    async with httpx.AsyncClient() as client:
        api = TelegramAPI(token, client)

        me = await api.call("getMe")
        if not me.get("ok"):
            logger.error(f"Telegram bot: invalid token or API error: {me}")
            return
        logger.info(f"Telegram bot logged in as @{me['result']['username']}")

        while True:
            try:
                updates = await api.get_updates(offset=offset, timeout=25)
            except asyncio.CancelledError:
                logger.info("Telegram bot polling cancelled.")
                return
            except Exception as e:
                logger.warning(f"Telegram bot polling error: {e}")
                await asyncio.sleep(5)
                continue

            for update in updates:
                offset = update["update_id"] + 1
                try:
                    await _dispatch(api, update, load_data_fn, save_data_fn, generate_vpn_link_fn)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    logger.exception(f"Telegram bot: error handling update {update['update_id']}: {e}")


async def _dispatch(api: TelegramAPI, update: dict, load_data_fn: Callable, save_data_fn: Callable, generate_vpn_link_fn: Callable):
    # --- Text messages ---
    if "message" in update:
        msg = update["message"]
        text = msg.get("text", "")
        tg_id = str(msg.get("from", {}).get("id", ""))

        if text.startswith("/cancel"):
            if tg_id in _pending_profile_create:
                _pending_profile_create.pop(tg_id, None)
                await api.send_message(msg["chat"]["id"], "Создание профиля отменено.")
            else:
                await api.send_message(msg["chat"]["id"], "Нет активной операции создания профиля.")
            return

        if tg_id in _pending_profile_create and not text.startswith("/"):
            await _handle_profile_name_input(
                api,
                msg,
                tg_id,
                _pending_profile_create[tg_id],
                load_data_fn,
                save_data_fn,
                generate_vpn_link_fn,
            )
            return

        if text.startswith("/start"):
            await _handle_start(api, msg, load_data_fn)
        elif text.startswith("/connections"):
            # Alias for /start
            await _handle_start(api, msg, load_data_fn)

    # --- Inline button callbacks ---
    elif "callback_query" in update:
        cq = update["callback_query"]
        callback_id = cq["id"]
        data_str = cq.get("data", "")
        chat_id = cq["message"]["chat"]["id"]
        message_id = cq["message"]["message_id"]
        tg_id = str(cq["from"]["id"])

        if data_str == "refresh":
            await _handle_refresh(api, chat_id, message_id, callback_id, tg_id, load_data_fn)
        elif data_str == "new:start":
            await _handle_new_start(api, chat_id, message_id, callback_id, tg_id, load_data_fn)
        elif data_str.startswith("new:srv:"):
            try:
                sid = int(data_str.split(":")[2])
            except Exception:
                await api.answer_callback(callback_id, "Bad server id")
                return
            await _handle_new_server(api, chat_id, message_id, callback_id, tg_id, sid, load_data_fn)
        elif data_str.startswith("new:proto:"):
            try:
                _, _, sid_raw, proto = data_str.split(":", 3)
                sid = int(sid_raw)
            except Exception:
                await api.answer_callback(callback_id, "Bad callback payload")
                return
            await _handle_new_protocol(
                api, chat_id, message_id, callback_id, tg_id, sid, proto,
                load_data_fn, save_data_fn, generate_vpn_link_fn,
            )
        elif data_str == "del:start":
            await _handle_delete_start(api, chat_id, message_id, callback_id, tg_id, load_data_fn)
        elif data_str.startswith("del:"):
            connection_id = data_str[4:]
            await _handle_delete_connection(
                api, chat_id, message_id, callback_id, tg_id, connection_id,
                load_data_fn, save_data_fn,
            )
        elif data_str.startswith("cfg:"):
            conn_id = data_str[4:]
            await _handle_get_config(
                api, chat_id, message_id, callback_id,
                conn_id, tg_id, load_data_fn, generate_vpn_link_fn
            )
