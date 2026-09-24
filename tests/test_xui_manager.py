"""Tests for the 3x-ui client layer. HTTP is served by an in-memory fake panel."""

import json
import re
import unittest
from urllib.parse import unquote

import httpx

from managers import xui_manager as xui

API_URL = 'http://xui.test:2053/basepath'
SUB_URI = 'https://sub.example.test:2096/subpath/'
TOKEN = 'test-token'

INBOUNDS = [
    {'id': 1, 'protocol': 'vless', 'enable': True, 'remark': 's3-vless'},
    {'id': 3, 'protocol': 'vless', 'enable': True, 'remark': 's4-vless'},
    {'id': 4, 'protocol': 'amneziawg', 'enable': True, 'remark': 's4-awg'},
    {'id': 5, 'protocol': 'hysteria', 'enable': True, 'remark': 's3-hy2'},
    {'id': 9, 'protocol': 'vless', 'enable': False, 'remark': 'disabled'},
]
WANTED = [1, 3, 5]

USER = {'id': 'c36e9e37-0000-4000-8000-000000000001', 'username': 'alice', 'telegramId': '318134970', 'enabled': True}


class FakeXUI:
    """Just enough of the 3x-ui v3.8.5 `/panel/api` to exercise the client layer."""

    def __init__(self, inbounds=None):
        self.inbounds = [dict(i) for i in (inbounds if inbounds is not None else INBOUNDS)]
        self.clients = {}  # email -> record (client fields + inboundIds)
        self.requests = []
        self.fail_inbounds = set()  # inbound ids whose attach fails, like an offline node
        self.next_row = 10

    def seed(self, email, inbound_ids, **fields):
        record = {
            'id': self.next_row, 'email': email, 'uuid': f"uuid-{email}", 'auth': f"auth-{email}",
            'flow': 'xtls-rprx-vision', 'subId': f"sub-{email}", 'tgId': 0, 'comment': 'seeded',
            'enable': True, 'allowedIPs': '10.9.1.2/32', 'inboundIds': list(inbound_ids),
        }
        record.update(fields)
        self.next_row += 1
        self.clients[email] = record
        return record

    @staticmethod
    def ok(obj=None, msg=''):
        return httpx.Response(200, json={'success': True, 'msg': msg, 'obj': obj})

    @staticmethod
    def fail(msg):
        return httpx.Response(200, json={'success': False, 'msg': msg, 'obj': None})

    def _attach(self, record, inbound_ids):
        errors = []
        for iid in inbound_ids:
            if iid in self.fail_inbounds:
                errors.append(f"inbound {iid}: context deadline exceeded")
            elif iid not in record['inboundIds']:
                record['inboundIds'].append(iid)
        return errors

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url, body, request.headers.get('authorization')))
        if request.headers.get('authorization') != f"Bearer {TOKEN}":
            return httpx.Response(401)
        path = unquote(request.url.path).removeprefix('/basepath/panel/api/')

        if request.method == 'GET' and path == 'inbounds/list':
            return self.ok(self.inbounds)
        if request.method == 'GET' and path == 'clients/list':
            return self.ok([dict(r) for r in self.clients.values()])
        if m := re.fullmatch(r'clients/get/(.+)', path):
            record = self.clients.get(m[1])
            if record is None:
                return self.fail('Obtain (record not found)')
            client = {k: v for k, v in record.items() if k != 'inboundIds'}
            return self.ok({'client': client, 'inboundIds': list(record['inboundIds']), 'externalLinks': []})
        if path == 'clients/add':
            client = body['client']
            if client['email'] in self.clients:
                return self.fail('email already exists')
            record = {**client, 'uuid': client['id'], 'id': self.next_row, 'inboundIds': []}
            self.next_row += 1
            self.clients[client['email']] = record
            errors = self._attach(record, body['inboundIds'])
            return self.fail('\n'.join(errors)) if errors else self.ok()
        if m := re.fullmatch(r'clients/update/(.+)', path):
            record = self.clients.get(m[1])
            if record is None:
                return self.fail('Obtain (record not found)')
            # Row replacement, like the real endpoint: omitted fields are lost.
            new = {k: v for k, v in body.items()}
            new['uuid'] = body.get('id')
            new['id'] = record['id']
            new['inboundIds'] = record['inboundIds']
            self.clients[m[1]] = new
            return self.ok(msg='Client updated')
        if m := re.fullmatch(r'clients/del/(.+)', path):
            if self.clients.pop(m[1], None) is None:
                return self.fail(f'Something went wrong (client "{m[1]}" not found in any inbound or client record\n)')
            return self.ok(msg='Client deleted')
        if m := re.fullmatch(r'clients/(.+)/attach', path):
            errors = self._attach(self.clients[m[1]], body['inboundIds'])
            return self.fail('\n'.join(errors)) if errors else self.ok()
        if path == 'clients/bulkAttach':
            attached, errors = [], []
            for email in body['emails']:
                errs = self._attach(self.clients[email], body['inboundIds'])
                (errors.extend(errs) if errs else attached.append(email))
            return self.ok({'attached': attached, 'skipped': [], 'errors': errors})
        if path in ('clients/bulkEnable', 'clients/bulkDisable'):
            enable = path.endswith('Enable')
            changed, skipped = 0, []
            for email in body['emails']:
                if email in self.clients:
                    self.clients[email]['enable'] = enable
                    changed += 1
                else:
                    skipped.append({'email': email, 'reason': 'client not found'})
            return self.ok({'changed': changed, 'skipped': skipped})
        return httpx.Response(404)

    def calls(self, method, path_suffix):
        return [r for r in self.requests if r[0] == method and unquote(r[1].path).endswith(path_suffix)]


def make_client(fake: FakeXUI, token: str = TOKEN) -> xui.XUIClient:
    config = xui.XUIConfig(api_url=API_URL, token=token, sub_uri=SUB_URI)
    return xui.XUIClient(config, transport=httpx.MockTransport(fake.handler))


class ConfigTests(unittest.TestCase):
    def test_incomplete_env_disables_integration(self):
        self.assertIsNone(xui.XUIConfig.from_env({}))
        self.assertIsNone(xui.XUIConfig.from_env({'XUI_API_URL': API_URL, 'XUI_API_TOKEN': TOKEN}))

    def test_full_env(self):
        config = xui.XUIConfig.from_env({
            'XUI_API_URL': API_URL + '/', 'XUI_API_TOKEN': TOKEN, 'XUI_SUB_URI': SUB_URI, 'XUI_TIMEOUT': '5',
        })
        self.assertEqual(config.api_url, API_URL)
        self.assertEqual(config.timeout, 5.0)
        self.assertNotIn(TOKEN, repr(config))

    def test_subscription_url_joins_once(self):
        for prefix in (SUB_URI, SUB_URI.rstrip('/')):
            config = xui.XUIConfig(api_url=API_URL, token=TOKEN, sub_uri=prefix)
            self.assertEqual(config.subscription_url('abc'), 'https://sub.example.test:2096/subpath/abc')


class HelperTests(unittest.TestCase):
    def test_only_enabled_vless_and_hysteria_inbounds(self):
        self.assertEqual(xui.subscription_inbound_ids(INBOUNDS), WANTED)

    def test_email_is_stable_per_panel_user(self):
        self.assertEqual(xui.client_email(USER), 'u-' + USER['id'])
        self.assertEqual(xui.client_email({**USER, 'telegramId': None}), xui.client_email(USER))

    def test_telegram_id(self):
        self.assertEqual(xui.telegram_id(USER), 318134970)
        self.assertEqual(xui.telegram_id({'telegramId': '@alice'}), 0)
        self.assertEqual(xui.telegram_id({}), 0)

    def test_new_client_sets_every_secret_explicitly(self):
        client = xui.new_client(USER)
        self.assertRegex(client['id'], r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
        self.assertRegex(client['auth'], r'^[0-9a-f]{32}$')
        self.assertRegex(client['subId'], r'^[0-9a-f]{16}$')
        self.assertEqual(client['flow'], 'xtls-rprx-vision')
        self.assertEqual(client['tgId'], 318134970)
        self.assertEqual(client['comment'], 'alice')
        self.assertTrue(client['enable'])
        self.assertNotEqual(xui.new_client(USER)['auth'], client['auth'])


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_sends_bearer_token_under_base_path(self):
        fake = FakeXUI()
        async with make_client(fake) as client:
            await client.list_inbounds()
        _, url, _, auth = fake.requests[0]
        self.assertEqual(str(url), f"{API_URL}/panel/api/inbounds/list")
        self.assertEqual(auth, f"Bearer {TOKEN}")

    async def test_http_error_raises(self):
        async with make_client(FakeXUI(), token='wrong') as client:
            with self.assertRaisesRegex(xui.XUIError, 'HTTP 401'):
                await client.list_inbounds()

    async def test_transport_error_raises(self):
        def boom(request):
            raise httpx.ConnectError('connection refused', request=request)

        config = xui.XUIConfig(api_url=API_URL, token=TOKEN, sub_uri=SUB_URI)
        async with xui.XUIClient(config, transport=httpx.MockTransport(boom)) as client:
            with self.assertRaisesRegex(xui.XUIError, 'ConnectError'):
                await client.list_inbounds()

    async def test_success_false_raises_with_message(self):
        fake = FakeXUI()
        fake.seed('u-x', [1])
        async with make_client(fake) as client:
            with self.assertRaisesRegex(xui.XUIError, 'email already exists'):
                await client.add_client({'email': 'u-x', 'id': 'i'}, [1])

    async def test_get_missing_client_is_none(self):
        async with make_client(FakeXUI()) as client:
            self.assertIsNone(await client.get_client('nobody'))

    async def test_update_sends_full_record_with_uuid_as_id(self):
        fake = FakeXUI()
        fake.seed('u-x', [1, 5], tgId=5, comment='keep me', allowedIPsByInbound={'4': '10.9.2.2/32'})
        async with make_client(fake) as client:
            await client.update_client('u-x', {'enable': False})
        body = fake.calls('POST', 'clients/update/u-x')[0][2]
        self.assertEqual(body['id'], 'uuid-u-x')
        self.assertNotIn('allowedIPs', body)
        self.assertNotIn('allowedIPsByInbound', body)
        self.assertFalse(body['enable'])
        # Nothing else was wiped by the row replacement.
        stored = fake.clients['u-x']
        for key, value in {'flow': 'xtls-rprx-vision', 'tgId': 5, 'comment': 'keep me',
                           'auth': 'auth-u-x', 'subId': 'sub-u-x', 'uuid': 'uuid-u-x'}.items():
            self.assertEqual(stored[key], value, key)

    async def test_update_refuses_record_without_uuid(self):
        fake = FakeXUI()
        fake.seed('u-x', [1], uuid='')
        async with make_client(fake) as client:
            with self.assertRaisesRegex(xui.XUIError, 'no uuid'):
                await client.update_client('u-x', {'enable': False})
        self.assertEqual(fake.calls('POST', 'clients/update/u-x'), [])

    async def test_delete(self):
        fake = FakeXUI()
        fake.seed('u-x', [1])
        async with make_client(fake) as client:
            self.assertTrue(await client.delete_client('u-x'))
            self.assertFalse(await client.delete_client('u-x'))
        self.assertEqual(fake.calls('POST', 'clients/del/u-x')[0][1].params['keepTraffic'], '0')

    async def test_email_is_path_escaped(self):
        fake = FakeXUI()
        async with make_client(fake) as client:
            await client.get_client('a/b c')
        self.assertIn('a%2Fb%20c', fake.requests[0][1].raw_path.decode())


class EnsureSubscriptionTests(unittest.IsolatedAsyncioTestCase):
    async def test_creates_client_on_vless_and_hysteria_only(self):
        fake = FakeXUI()
        async with make_client(fake) as client:
            sub = await xui.ensure_subscription(client, USER)
        add = fake.calls('POST', 'clients/add')
        self.assertEqual(len(add), 1)
        body = add[0][2]
        self.assertEqual(body['inboundIds'], WANTED)
        self.assertEqual(body['client']['email'], 'u-' + USER['id'])
        for key in ('id', 'auth', 'flow', 'subId'):
            self.assertTrue(body['client'][key], key)
        self.assertTrue(sub.created)
        self.assertEqual(sub.sub_id, body['client']['subId'])
        self.assertEqual(sub.url, SUB_URI + body['client']['subId'])
        self.assertEqual(sub.missing_inbound_ids, [])

    async def test_second_call_reuses_existing_client(self):
        fake = FakeXUI()
        async with make_client(fake) as client:
            first = await xui.ensure_subscription(client, USER)
            second = await xui.ensure_subscription(client, USER)
        self.assertEqual(len(fake.calls('POST', 'clients/add')), 1)
        self.assertEqual(first.url, second.url)
        self.assertFalse(second.created)
        self.assertEqual(fake.calls('POST', '/attach'), [])

    async def test_existing_client_gets_attached_to_new_inbounds(self):
        fake = FakeXUI()
        fake.seed(xui.client_email(USER), [1], subId='0123456789abcdef')
        async with make_client(fake) as client:
            sub = await xui.ensure_subscription(client, USER)
        self.assertEqual(fake.calls('POST', 'clients/add'), [])
        self.assertEqual(fake.calls('POST', '/attach')[0][2], {'inboundIds': [3, 5]})
        self.assertEqual(sub.url, SUB_URI + '0123456789abcdef')
        self.assertEqual(sorted(sub.inbound_ids), WANTED)

    async def test_partial_add_still_returns_subscription(self):
        fake = FakeXUI()
        fake.fail_inbounds = {3}
        async with make_client(fake) as client:
            sub = await xui.ensure_subscription(client, USER)
        self.assertEqual(sub.missing_inbound_ids, [3])
        self.assertTrue(sub.errors)
        self.assertEqual(sorted(sub.inbound_ids), [1, 5])

    async def test_failed_add_raises(self):
        fake = FakeXUI()

        def handler(request):
            if request.url.path.endswith('clients/add'):
                return FakeXUI.fail('inbound 1: boom')
            return fake.handler(request)

        config = xui.XUIConfig(api_url=API_URL, token=TOKEN, sub_uri=SUB_URI)
        async with xui.XUIClient(config, transport=httpx.MockTransport(handler)) as client:
            with self.assertRaisesRegex(xui.XUIError, 'boom'):
                await xui.ensure_subscription(client, USER)

    async def test_no_inbounds_raises_before_creating(self):
        fake = FakeXUI(inbounds=[{'id': 4, 'protocol': 'amneziawg', 'enable': True}])
        async with make_client(fake) as client:
            with self.assertRaisesRegex(xui.XUIError, 'no enabled VLESS/Hysteria'):
                await xui.ensure_subscription(client, USER)
        self.assertEqual(fake.calls('POST', 'clients/add'), [])


class PanelMirrorTests(unittest.IsolatedAsyncioTestCase):
    async def test_pause_and_resume(self):
        fake = FakeXUI()
        fake.seed(xui.client_email(USER), WANTED)
        async with make_client(fake) as client:
            await xui.set_user_enabled(client, [USER, {'id': 'no-client'}], False)
            self.assertFalse(fake.clients[xui.client_email(USER)]['enable'])
            await xui.set_user_enabled(client, [USER], True)
        self.assertTrue(fake.clients[xui.client_email(USER)]['enable'])
        self.assertEqual(fake.calls('POST', 'clients/bulkDisable')[0][2]['emails'], ['u-' + USER['id'], 'u-no-client'])

    async def test_delete_user(self):
        fake = FakeXUI()
        fake.seed(xui.client_email(USER), WANTED)
        async with make_client(fake) as client:
            self.assertTrue(await xui.delete_user(client, USER))
        self.assertNotIn(xui.client_email(USER), fake.clients)


class SyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_sync_attaches_mirrors_and_reports(self):
        fake = FakeXUI()
        paused = {'id': 'p', 'username': 'bob', 'enabled': False, 'telegramId': ''}
        relinked = {'id': 'r', 'username': 'carol', 'enabled': True, 'telegramId': '42'}
        fake.seed(xui.client_email(USER), [1], tgId=318134970)
        fake.seed(xui.client_email(paused), [1], enable=True)
        fake.seed(xui.client_email(relinked), WANTED, tgId=0)
        fake.seed('u-gone', WANTED)
        fake.seed('the80hz-test', [1])  # not panel-owned: left alone
        async with make_client(fake) as client:
            report = await xui.sync_all(client, [USER, paused, relinked, {'id': 'never-subscribed'}])

        self.assertEqual(report.clients, 3)
        self.assertEqual(report.attached, {'u-' + USER['id']: [3, 5], 'u-p': [3, 5]})
        bulk = fake.calls('POST', 'clients/bulkAttach')
        self.assertEqual(len(bulk), 1)  # both miss the same inbounds: one call
        self.assertEqual(report.disabled, ['u-p'])
        self.assertFalse(fake.clients['u-p']['enable'])
        self.assertEqual(report.tg_updated, ['u-r'])
        self.assertEqual(fake.clients['u-r']['tgId'], 42)
        self.assertEqual(fake.clients['u-r']['flow'], 'xtls-rprx-vision')
        self.assertEqual(report.orphans, ['u-gone'])
        self.assertIn('u-gone', fake.clients)
        self.assertEqual(fake.clients['the80hz-test']['inboundIds'], [1])
        self.assertEqual(fake.calls('POST', 'clients/add'), [])
        self.assertEqual(report.errors, [])

    async def test_sync_reports_attach_errors(self):
        fake = FakeXUI()
        fake.fail_inbounds = {3}
        fake.seed(xui.client_email(USER), [1])
        async with make_client(fake) as client:
            report = await xui.sync_all(client, [USER])
        self.assertEqual(report.attached, {})
        self.assertEqual(len(report.errors), 1)


if __name__ == '__main__':
    unittest.main()
