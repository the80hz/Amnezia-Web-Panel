"""
3x-ui subscription integration.

Panel users get one client on a central 3x-ui panel, attached to every VLESS and
Hysteria inbound it serves, and receive that client's subscription URL. AWG stays
with this panel: 3x-ui AmneziaWG inbounds are never handed out.

Configuration comes from the environment (the token is never stored in data.json):

    XUI_API_URL    panel URL including the random basePath,
                   e.g. http://192.168.0.120:2053/ccb51fcade00942d59
    XUI_API_TOKEN  Bearer token (Settings -> Security -> API Token)
    XUI_SUB_URI    public subscription prefix, the panel's `subURI` setting,
                   e.g. https://sub.gruz200.uk:2096/7naaj5hyiha6xn1n/
    XUI_TIMEOUT    optional request timeout in seconds (default 30)

3x-ui quirks this module works around:

* `clients/add` attached to several Hysteria inbounds mints a different `auth` per
  inbound but puts a single one into the links, so some nodes answer
  "auth failed code 404". `id`, `auth`, `flow` and `subId` are therefore always
  passed explicitly.
* `clients/update/{email}` replaces the row: omitted fields are wiped. Updates go
  through `update_client`, which sends the full record back.
"""

import asyncio
import logging
import os
import secrets
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Self
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

JSONObject = dict[str, Any]
User = Mapping[str, Any]

# Inbound protocols whose links go into the subscription. Everything else
# (amneziawg, wireguard, trojan, ...) is skipped.
SUBSCRIPTION_PROTOCOLS = frozenset({'vless', 'hysteria', 'hysteria2'})
VLESS_FLOW = 'xtls-rprx-vision'
EMAIL_PREFIX = 'u-'

# Serializes ensure_subscription so a double tap (bot and web share one event
# loop) cannot race two clients/add calls for the same email.
_ENSURE_LOCK = asyncio.Lock()

# Record-level fields that must not be echoed back on update: per-inbound AWG
# allocations; a string there fails to unmarshal on the 3x-ui side.
_UPDATE_DROP_FIELDS = ('allowedIPs', 'allowedIPsByInbound')


class XUIError(Exception):
    """A 3x-ui API call failed (transport error, HTTP error or success=false)."""


@dataclass(frozen=True)
class XUIConfig:
    api_url: str
    token: str = field(repr=False)
    sub_uri: str
    timeout: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> 'XUIConfig | None':
        """Build the config from the environment, or None when it is incomplete."""
        env = os.environ if env is None else env
        api_url = (env.get('XUI_API_URL') or '').strip().rstrip('/')
        token = (env.get('XUI_API_TOKEN') or '').strip()
        sub_uri = (env.get('XUI_SUB_URI') or '').strip()
        if not (api_url and token and sub_uri):
            return None
        try:
            timeout = float(env.get('XUI_TIMEOUT') or 30)
        except ValueError:
            timeout = 30.0
        return cls(api_url=api_url, token=token, sub_uri=sub_uri, timeout=timeout)

    def subscription_url(self, sub_id: str) -> str:
        return f"{self.sub_uri.rstrip('/')}/{sub_id}"


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []  # pyright: ignore[reportUnknownArgumentType]


def _as_object(value: Any) -> JSONObject:
    return dict(value) if isinstance(value, dict) else {}  # pyright: ignore[reportUnknownArgumentType]


def _inbound_ids(record: Mapping[str, Any]) -> list[int]:
    return [int(i) for i in _as_list(record.get('inboundIds'))]


def _is_not_found(message: str) -> bool:
    # clients/get says "Obtain (record not found)"; clients/del says
    # 'client "x" not found in any inbound or client record'.
    text = (message or '').lower()
    return 'record not found' in text or 'not found in any inbound' in text


class XUIClient:
    """Thin async wrapper over the 3x-ui `/panel/api` endpoints this panel needs."""

    def __init__(self, config: XUIConfig, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self._http = httpx.AsyncClient(
            base_url=f"{config.api_url}/panel/api/",
            headers={'Authorization': f"Bearer {config.token}", 'Accept': 'application/json'},
            timeout=config.timeout,
            transport=transport,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, *, json: Any = None, params: dict[str, Any] | None = None) -> Any:
        try:
            resp = await self._http.request(method, path, json=json, params=params)
        except httpx.HTTPError as e:
            raise XUIError(f"3x-ui {method} {path}: {type(e).__name__}: {e}") from e
        if resp.status_code != 200:
            raise XUIError(f"3x-ui {method} {path}: HTTP {resp.status_code}")
        try:
            payload: Any = resp.json()
        except ValueError as e:
            raise XUIError(f"3x-ui {method} {path}: response is not JSON") from e
        if not isinstance(payload, dict):
            raise XUIError(f"3x-ui {method} {path}: unexpected response")
        body: JSONObject = payload  # pyright: ignore[reportUnknownVariableType]
        if not body.get('success'):
            raise XUIError(f"3x-ui {method} {path}: {body.get('msg') or 'success=false'}")
        return body.get('obj')

    # --- inbounds -------------------------------------------------------- #

    async def list_inbounds(self) -> list[JSONObject]:
        return await self._request('GET', 'inbounds/list') or []

    # --- clients --------------------------------------------------------- #

    async def list_clients(self) -> list[JSONObject]:
        """All client records, each with its `inboundIds`."""
        return await self._request('GET', 'clients/list') or []

    async def get_client(self, email: str) -> JSONObject | None:
        """Return `{"client": {...}, "inboundIds": [...], ...}` or None if absent."""
        try:
            return await self._request('GET', f"clients/get/{quote(email, safe='')}")
        except XUIError as e:
            if _is_not_found(str(e)):
                return None
            raise

    async def add_client(self, client: JSONObject, inbound_ids: Iterable[int]) -> None:
        await self._request('POST', 'clients/add', json={'client': client, 'inboundIds': list(inbound_ids)})

    async def update_client(self, email: str, changes: Mapping[str, Any]) -> JSONObject:
        """Change some fields without wiping the rest.

        The endpoint replaces the whole row, so read the record, restore `id` to
        the client UUID (in the record `id` is the numeric DB row), drop the AWG
        allocation fields, apply the changes and send the full object back.
        """
        record = await self.get_client(email)
        if record is None:
            raise XUIError(f"3x-ui client {email!r} not found")
        body = _as_object(record.get('client'))
        client_uuid = body.get('uuid')
        if not client_uuid:
            raise XUIError(f"3x-ui client {email!r} has no uuid; refusing a lossy update")
        body['id'] = client_uuid
        for key in _UPDATE_DROP_FIELDS:
            body.pop(key, None)
        body.update(changes)
        await self._request('POST', f"clients/update/{quote(email, safe='')}", json=body)
        return body

    async def delete_client(self, email: str) -> bool:
        """Delete the client from every inbound. False if it did not exist."""
        try:
            await self._request('POST', f"clients/del/{quote(email, safe='')}", params={'keepTraffic': 0})
        except XUIError as e:
            if _is_not_found(str(e)):
                return False
            raise
        return True

    async def attach(self, email: str, inbound_ids: Iterable[int]) -> None:
        await self._request('POST', f"clients/{quote(email, safe='')}/attach", json={'inboundIds': list(inbound_ids)})

    async def bulk_attach(self, emails: Iterable[str], inbound_ids: Iterable[int]) -> JSONObject:
        return await self._request(
            'POST', 'clients/bulkAttach', json={'emails': list(emails), 'inboundIds': list(inbound_ids)}
        ) or {}

    async def bulk_set_enabled(self, emails: Iterable[str], enable: bool) -> JSONObject:
        path = 'clients/bulkEnable' if enable else 'clients/bulkDisable'
        return await self._request('POST', path, json={'emails': list(emails)}) or {}


# ------------------------------------------------------------------------- #
#  Panel-level operations
# ------------------------------------------------------------------------- #

def client_email(user: User) -> str:
    """Stable, unique 3x-ui email for a panel user, independent of Telegram linking."""
    return f"{EMAIL_PREFIX}{user['id']}"


def telegram_id(user: User) -> int:
    raw = str(user.get('telegramId') or '').strip().lstrip('@')
    return int(raw) if raw.isdigit() else 0


def subscription_inbound_ids(inbounds: Iterable[Mapping[str, Any]]) -> list[int]:
    """IDs of enabled VLESS/Hysteria inbounds, in panel order."""
    return [
        int(i['id'])
        for i in inbounds
        if str(i.get('protocol', '')).lower() in SUBSCRIPTION_PROTOCOLS and i.get('enable', True)
    ]


def new_client(user: User) -> JSONObject:
    """Client body for `clients/add` with every secret set explicitly."""
    return {
        'email': client_email(user),
        'id': str(uuid.uuid4()),
        'auth': secrets.token_hex(16),
        'flow': VLESS_FLOW,
        'subId': secrets.token_hex(8),
        'tgId': telegram_id(user),
        'comment': str(user.get('username') or '')[:100],
        'enable': bool(user.get('enabled', True)),
        'limitIp': 0,
        'totalGB': 0,
        'expiryTime': 0,
    }


@dataclass
class Subscription:
    email: str
    sub_id: str
    url: str
    created: bool
    inbound_ids: list[int]
    missing_inbound_ids: list[int]  # wanted but not attached (e.g. node offline)
    errors: list[str]


async def ensure_subscription(client: XUIClient, user: User) -> Subscription:
    """Return the user's subscription, creating or completing the 3x-ui client.

    Idempotent: an existing client is reused and only attached to inbounds it
    lacks. Partial failures (one node down) still yield a working subscription;
    they are reported in `missing_inbound_ids` / `errors`.
    """
    async with _ENSURE_LOCK:
        return await _ensure_subscription(client, user)


async def _ensure_subscription(client: XUIClient, user: User) -> Subscription:
    email = client_email(user)
    wanted = subscription_inbound_ids(await client.list_inbounds())
    if not wanted:
        raise XUIError('3x-ui has no enabled VLESS/Hysteria inbounds')

    errors: list[str] = []
    created = False
    record = await client.get_client(email)
    if record is None:
        try:
            await client.add_client(new_client(user), wanted)
        except XUIError as e:
            # Inbounds are applied independently: success=false may still have
            # created the client on the others. Re-read to find out.
            errors.append(str(e))
            logger.warning("3x-ui add for %s reported: %s", email, e)
        created = True
        record = await client.get_client(email)
        if record is None:
            raise XUIError(errors[0] if errors else f"3x-ui client {email!r} was not created")
    else:
        missing = [i for i in wanted if i not in set(_inbound_ids(record))]
        if missing:
            try:
                await client.attach(email, missing)
            except XUIError as e:
                errors.append(str(e))
                logger.warning("3x-ui attach for %s reported: %s", email, e)
            record = await client.get_client(email) or record

    attached = _inbound_ids(record)
    sub_id = str(_as_object(record.get('client')).get('subId') or '')
    if not sub_id:
        sub_id = secrets.token_hex(8)
        await client.update_client(email, {'subId': sub_id})
    return Subscription(
        email=email,
        sub_id=sub_id,
        url=client.config.subscription_url(sub_id),
        created=created,
        inbound_ids=attached,
        missing_inbound_ids=[i for i in wanted if i not in set(attached)],
        errors=errors,
    )


async def set_user_enabled(client: XUIClient, users: Iterable[User], enable: bool) -> JSONObject:
    """Mirror a panel pause/resume. Users without a 3x-ui client are skipped by 3x-ui."""
    emails = [client_email(u) for u in users]
    if not emails:
        return {}
    return await client.bulk_set_enabled(emails, enable)


async def delete_user(client: XUIClient, user: User) -> bool:
    return await client.delete_client(client_email(user))


@dataclass
class SyncReport:
    clients: int = 0
    attached: dict[str, list[int]] = field(default_factory=dict[str, list[int]])  # email -> inbound ids
    enabled: list[str] = field(default_factory=list[str])
    disabled: list[str] = field(default_factory=list[str])
    tg_updated: list[str] = field(default_factory=list[str])
    orphans: list[str] = field(default_factory=list[str])  # u-* clients with no panel user
    errors: list[str] = field(default_factory=list[str])


async def sync_all(client: XUIClient, users: Iterable[User]) -> SyncReport:
    """Bring every existing panel-owned client in line with the panel.

    Attaches clients to VLESS/Hysteria inbounds they lack (a new node or inbound),
    mirrors the panel's enabled flag and Telegram ID. Never creates or deletes
    clients: orphans are only reported.
    """
    report = SyncReport()
    wanted = subscription_inbound_ids(await client.list_inbounds())
    by_email = {client_email(u): u for u in users}
    records = {str(c.get('email')): c for c in await client.list_clients()}

    # Group by the set of missing inbounds so each group is one bulkAttach call.
    groups: dict[tuple[int, ...], list[str]] = {}
    for email, rec in records.items():
        user = by_email.get(email)
        if user is None:
            if email.startswith(EMAIL_PREFIX):
                report.orphans.append(email)
            continue
        report.clients += 1
        have = set(_inbound_ids(rec))
        missing = tuple(i for i in wanted if i not in have)
        if missing:
            groups.setdefault(missing, []).append(email)
        user_enabled = bool(user.get('enabled', True))
        if bool(rec.get('enable', True)) != user_enabled:
            (report.enabled if user_enabled else report.disabled).append(email)

    for inbound_ids, emails in groups.items():
        try:
            result = await client.bulk_attach(emails, inbound_ids)
        except XUIError as e:
            report.errors.append(str(e))
            continue
        report.errors.extend(str(err) for err in _as_list(result.get('errors')))
        attached = [str(e) for e in _as_list(result.get('attached'))] if 'attached' in result else emails
        for email in attached:
            report.attached[email] = list(inbound_ids)

    for emails, enable in ((report.enabled, True), (report.disabled, False)):
        if emails:
            try:
                await client.bulk_set_enabled(emails, enable)
            except XUIError as e:
                report.errors.append(str(e))

    for email, rec in records.items():
        user = by_email.get(email)
        if user is None:
            continue
        tg = telegram_id(user)
        if tg and int(rec.get('tgId') or 0) != tg:
            try:
                await client.update_client(email, {'tgId': tg})
                report.tg_updated.append(email)
            except XUIError as e:
                report.errors.append(str(e))
    return report
