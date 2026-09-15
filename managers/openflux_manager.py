"""
OpenFlux Manager — emergency whitelist-bypass channel.

Unlike every other protocol in this panel, OpenFlux cannot multiplex users:
the client address is hardcoded (10.10.10.2) and the transport doc relays as a
broadcast bus, so **one user == one Yandex document == one exit-node process**.
Each user brings their OWN public Yandex document (shared with edit-by-link) and
gets a dedicated container `amnezia-openflux-<client_id>` bound to that doc.

Traffic tunnels TCP inside the Yandex Docs realtime channel, so it keeps working
even when RKN enables an IP *whitelist* (Yandex stays reachable) — the scenario
where AmneziaWG / WireGuard / Xray-Reality all fail because the server IP is not
reachable at all. The end user connects with the **OpenFlux app** (iOS TestFlight
/ Android APK), picking the VOLGA transport and pasting the doc URL — there is no
downloadable .conf, so "config" here is a short instruction text.

Runs in **proxy mode** (image default: no `--mode` flag), which needs no
NET_RAW / NET_ADMIN — the container is unprivileged. DNS poisoning on the
client's network is solved client-side by the OpenFlux app (DoT / DNS-over-TCP),
so the exit node itself needs nothing special.
"""

import hashlib
import logging
import os
import re
import secrets
import shlex

logger = logging.getLogger(__name__)

# Tunables (override via env). Per-server cap protects small VPSs from OOM;
# per-user cap curbs abuse (read by the bot/panel add flows). App links are
# surfaced to users in the connection instructions.
OPENFLUX_MAX_PER_SERVER = int(os.environ.get('OPENFLUX_MAX_PER_SERVER', '10'))
OPENFLUX_MAX_PER_USER = int(os.environ.get('OPENFLUX_MAX_PER_USER', '3'))
OPENFLUX_IOS_URL = os.environ.get('OPENFLUX_IOS_URL', 'https://testflight.apple.com/join/BwnAcdus')
OPENFLUX_ANDROID_URL = os.environ.get('OPENFLUX_ANDROID_URL', 'https://github.com/p1neappleXpress/OpenFluxAndroid/releases')

# Yandex-only URL allowlist (host part). A shared doc opens via disk.yandex.ru/i/...
_YANDEX_URL_RE = re.compile(r'^https://([A-Za-z0-9-]+\.)*yandex\.(ru|com)/', re.IGNORECASE)


def _short_id(nbytes: int = 5) -> str:
    return secrets.token_hex(max(4, nbytes))


class OpenFluxManager:
    PROTOCOL = 'openflux'
    IMAGE_NAME = 'amnezia-openflux:latest'
    CONTAINER_PREFIX = 'amnezia-openflux'          # per-user: amnezia-openflux-<client_id>
    BUILD_DIR = '/opt/amnezia/openflux'
    REPO_URL = 'https://github.com/p1neappleXpress/OpenFlux.git'
    DEFAULT_TRANSPORT = 'vyandex'                   # app tab: VOLGA
    MEMORY_LIMIT = '350m'
    VALIDATE_TIMEOUT = 25                           # seconds to wait for "WS connected"
    BUILD_LOG = '/opt/amnezia/openflux/build.log'   # async image build log
    BUILD_FAILED = '/opt/amnezia/openflux/.build_failed'
    REPO_DIR = '/opt/amnezia/openflux/repo'         # git clone / docker build context

    def __init__(self, ssh, protocol='openflux'):
        self.ssh = ssh
        self.protocol = protocol or self.PROTOCOL

    # ---------------------------------------------------------------- naming
    def _container_name(self, client_id) -> str:
        cid = re.sub(r'[^A-Za-z0-9_.-]', '', str(client_id))[:40]
        return f'{self.CONTAINER_PREFIX}-{cid}'

    # =========================================================== STATUS
    def check_docker_installed(self) -> bool:
        out, _, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, _ = self.ssh.run_command(
            "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null"
        )
        return 'active' in out2 or 'running' in out2.lower()

    def _image_present(self) -> bool:
        out, _, _ = self.ssh.run_sudo_command(f"docker images -q {self.IMAGE_NAME} 2>/dev/null")
        return bool(out.strip())

    def check_protocol_installed(self, protocol_type='openflux') -> bool:
        # "Installed" == the exit-node image has been built on this server.
        return self._image_present()

    def _list_client_containers(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.CONTAINER_PREFIX}- --format '{{{{.Names}}}} {{{{.Status}}}}'"
        )
        rows = []
        for line in out.strip().splitlines():
            line = line.strip()
            if not line or line.startswith(f'{self.CONTAINER_PREFIX}-validate'):
                continue
            parts = line.split(' ', 1)
            rows.append({'name': parts[0], 'status': parts[1] if len(parts) > 1 else ''})
        return rows

    def check_container_running(self, protocol_type='openflux') -> bool:
        return any(c['status'].startswith('Up') for c in self._list_client_containers())

    def _build_in_progress(self) -> bool:
        # Bracket the first char so pgrep does NOT match its own wrapping shell:
        # paramiko runs commands via `sh -c '<cmd>'`, whose cmdline contains the
        # pattern, so a plain pattern self-matches and always returns "yes"
        # (which made install_protocol think a build was always running and never
        # launch one). `[o]penflux` matches a real build's cmdline but not the
        # literal "[o]penflux" text in the pgrep command itself.
        out, _, _ = self.ssh.run_sudo_command(
            "pgrep -f '[o]penflux/_build.sh|[d]ocker build -t amnezia-openflux' >/dev/null 2>&1 && echo yes || echo no"
        )
        return 'yes' in out

    def _build_failed(self) -> bool:
        out, _, _ = self.ssh.run_sudo_command(f"test -f {shlex.quote(self.BUILD_FAILED)} && echo yes || echo no")
        return 'yes' in out

    def _container_exists(self, name) -> bool:
        out, _, _ = self.ssh.run_sudo_command(f"docker ps -a --filter name=^{name}$ --format '{{{{.Names}}}}'")
        return name in out.strip().split('\n')

    def get_server_status(self, protocol_type='openflux') -> dict:
        installed = self._image_present()
        building = (not installed) and self._build_in_progress()
        build_failed = (not installed) and (not building) and self._build_failed()
        clients = self._list_client_containers() if installed else []
        running = sum(1 for c in clients if c['status'].startswith('Up'))
        return {
            'container_exists': installed,
            'container_running': running > 0,
            'building': building,
            'build_failed': build_failed,
            'image': self.IMAGE_NAME,
            'protocol': 'openflux',
            'base_protocol': self.PROTOCOL,
            'instance': 1,
            'clients_total': len(clients),
            'clients_running': running,
        }

    def get_clients(self, protocol=None):
        # OpenFlux connections are created per-user via the bot/panel and are
        # always tracked in data.json, so there are no "unassigned" server-side
        # clients to surface here.
        return []

    # ================================================ INSTALL / UNINSTALL
    def install_protocol(self, protocol_type='openflux', port=None, repo_url=None, rebuild=False, **_):
        if not self.check_docker_installed():
            return {'status': 'error', 'message': 'Docker not installed'}
        repo_url = repo_url or self.REPO_URL

        if self._image_present() and not rebuild:
            return {
                'status': 'success',
                'protocol': 'openflux',
                'base_protocol': self.PROTOCOL,
                'image': self.IMAGE_NAME,
                'message': 'OpenFlux image already present',
                'log': ['OpenFlux exit-node image already built on this server.'],
            }

        if self._build_in_progress():
            return {'status': 'building', 'protocol': 'openflux', 'base_protocol': self.PROTOCOL,
                    'message': 'OpenFlux image build already in progress',
                    'log': ['Сборка образа уже идёт — статус обновится, когда образ будет готов.']}
        # The Go image build takes minutes. Run it fully DETACHED (setsid) AND as
        # root: run_sudo_script runs the WHOLE script under sudo, unlike a sudo'd
        # one-liner where only the first command before ';' is elevated. The HTTP
        # request returns immediately; get_server_status reports 'building' (pgrep)
        # and 'build_failed' (marker file). buildx is ensured for BuildKit caches.
        launcher = "\n".join([
            "#!/bin/bash",
            "set -u",
            f"mkdir -p {self.BUILD_DIR}",
            f"rm -f {self.BUILD_FAILED}",
            f"cat > {self.BUILD_DIR}/_build.sh <<'OFXBUILD'",
            "set -e",
            "if ! docker buildx version >/dev/null 2>&1; then",
            "  export DEBIAN_FRONTEND=noninteractive",
            "  apt-get install -y docker-buildx >/dev/null 2>&1 || apt-get install -y docker-buildx-plugin >/dev/null 2>&1 || true",
            "fi",
            f"if [ -d {self.REPO_DIR}/.git ]; then",
            f"  git -C {self.REPO_DIR} fetch --depth 1 origin && git -C {self.REPO_DIR} reset --hard FETCH_HEAD",
            "else",
            f"  rm -rf {self.REPO_DIR} && git clone --depth 1 {repo_url} {self.REPO_DIR}",
            "fi",
            f"DOCKER_BUILDKIT=1 docker build -t {self.IMAGE_NAME} {self.REPO_DIR}",
            "OFXBUILD",
            f"setsid bash -c 'bash {self.BUILD_DIR}/_build.sh > {self.BUILD_LOG} 2>&1 || touch {self.BUILD_FAILED}' </dev/null >/dev/null 2>&1 &",
        ])
        _, err, code = self.ssh.run_sudo_script(launcher, timeout=60)
        if code != 0:
            return {'status': 'error', 'message': f'Failed to start build: {(err or "").strip()[:200]}'}
        return {
            'status': 'building',
            'protocol': 'openflux',
            'base_protocol': self.PROTOCOL,
            'image': self.IMAGE_NAME,
            'message': 'OpenFlux image build started in background',
            'log': [
                'Сборка образа OpenFlux запущена в фоне (~2–5 мин).',
                'Статус обновится автоматически, когда образ будет готов.',
            ],
        }

    def uninstall_protocol(self, protocol_type='openflux'):
        for c in self._list_client_containers():
            self.ssh.run_sudo_command(f"docker rm -f {shlex.quote(c['name'])} || true")
        self.ssh.run_sudo_command(f"docker rmi -f {self.IMAGE_NAME} || true")
        self.ssh.run_sudo_command(f"rm -rf {shlex.quote(self.BUILD_DIR)}")
        return {'status': 'success', 'message': 'OpenFlux removed'}

    # Aliases so the panel's uninstall dispatch finds a method regardless of name.
    # The uninstall endpoint calls manager.remove_container(protocol); for OpenFlux
    # that means tearing down every per-user exit container + the shared image.
    def remove_container(self, protocol_type='openflux'):
        return self.uninstall_protocol(protocol_type)

    def remove_protocol(self, protocol_type='openflux'):
        return self.uninstall_protocol(protocol_type)

    def uninstall(self, protocol_type='openflux'):
        return self.uninstall_protocol(protocol_type)

    # ============================================================ VALIDATION
    def validate_doc(self, doc_url, transport=None):
        """Test-join the doc in a throwaway container. Returns (ok, reason)."""
        transport = transport or self.DEFAULT_TRANSPORT
        if not _YANDEX_URL_RE.match(doc_url or ''):
            return False, 'URL must be a Yandex document link (https://disk.yandex.ru/...)'
        if not self._image_present():
            return False, 'OpenFlux is not installed on this server'

        tmp = f"{self.CONTAINER_PREFIX}-validate-{_short_id(4)}"
        run = (
            f"docker run -d --name {tmp} --memory {self.MEMORY_LIMIT} "
            f"-e ROLE=exit-node -e TRANSPORT={shlex.quote(transport)} "
            f"-e URL={shlex.quote(doc_url)} -e DEBUG=1 {self.IMAGE_NAME}"
        )
        _, err, code = self.ssh.run_sudo_command(run, timeout=60)
        if code != 0:
            return False, f'could not start validator: {(err or "").strip()[:200]}'
        try:
            poll = (
                f"for i in $(seq 1 {self.VALIDATE_TIMEOUT}); do "
                f"  if docker logs {tmp} 2>&1 | grep -q 'WS connected'; then echo OFX_OK; break; fi; "
                f"  if ! docker ps -q --filter name=^{tmp}$ | grep -q .; then break; fi; "
                "  sleep 1; "
                "done; "
                "echo '---LOGTAIL---'; "
                f"docker logs {tmp} 2>&1 | tail -8"
            )
            out, _, _ = self.ssh.run_sudo_command(poll, timeout=self.VALIDATE_TIMEOUT + 20)
        finally:
            self.ssh.run_sudo_command(f"docker rm -f {tmp} || true")

        if 'OFX_OK' in out:
            return True, 'authorized + realtime channel connected'
        tail = out.split('---LOGTAIL---', 1)[-1].strip().lower()
        reason = 'could not join the document — is it public with EDIT rights?'
        for pat in ('client-config not found', 'login', 'passport', 'redirect', 'no ipv4'):
            if pat in tail:
                reason = f'{reason} (hint: {pat})'
                break
        return False, reason

    # ==================================================== CONNECTIONS (per user)
    def _doc_in_use(self, doc_url):
        """(in_use, container_name) — True if a (non-validate) exit-node container
        is already bound to this doc. One doc == one tunnel: a second exit node on
        the same document collides with the first and breaks both."""
        for c in self._list_client_containers():
            out, _, _ = self.ssh.run_sudo_command(
                "docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "
                + shlex.quote(c['name']) + " 2>/dev/null"
            )
            if any(line.strip() == f"URL={doc_url}" for line in out.splitlines()):
                return True, c['name']
        return False, None

    def add_client(self, protocol, name, host, port, doc_url=None, transport=None):
        """Start a dedicated exit-node container for the user's doc.
        The container name is derived from the doc URL (deterministic), so a
        duplicate is refused and a concurrent duplicate loses the docker --name
        race atomically. Dedup is checked BEFORE validation so we never open a
        second session on a doc that already has a live tunnel."""
        transport = transport or self.DEFAULT_TRANSPORT
        doc_url = (doc_url or '').strip()
        if not _YANDEX_URL_RE.match(doc_url):
            return {'status': 'error', 'message': 'URL must be a Yandex document link (https://disk.yandex.ru/...)'}
        if not self._image_present():
            return {'status': 'error', 'message': 'OpenFlux is not installed on this server'}

        client_id = hashlib.sha1(doc_url.encode('utf-8')).hexdigest()[:12]
        container = self._container_name(client_id)

        if self._container_exists(container):
            return {'status': 'error', 'message': (
                'Этот документ уже используется другим подключением. '
                'На один документ можно только одно активное подключение — '
                'создайте новый Яндекс.Документ для второго туннеля.'
            )}
        if len(self._list_client_containers()) >= OPENFLUX_MAX_PER_SERVER:
            return {'status': 'error', 'message': (
                f'Сервер заполнен (лимит {OPENFLUX_MAX_PER_SERVER} туннелей OpenFlux). '
                'Выберите другой сервер.'
            )}

        ok, reason = self.validate_doc(doc_url, transport)
        if not ok:
            return {'status': 'error', 'message': reason}

        run = (
            f"docker run -d --name {container} --restart unless-stopped "
            f"--memory {self.MEMORY_LIMIT} "
            f"-e ROLE=exit-node -e TRANSPORT={shlex.quote(transport)} "
            f"-e URL={shlex.quote(doc_url)} {self.IMAGE_NAME}"
        )
        _, err, code = self.ssh.run_sudo_command(run, timeout=60)
        if code != 0:
            return {'status': 'error', 'message': (
                'Не удалось создать туннель (возможно, документ уже используется). '
                + (err or '').strip()[:150]
            )}
        return {
            'status': 'success',
            'client_id': client_id,
            'container_name': container,
            'doc_url': doc_url,
            'transport': transport,
            'name': name,
            'instructions': self.build_instructions(doc_url, transport),
            'config': '',  # app-based; no downloadable config / vpn:// link
        }

    def remove_client(self, protocol, client_id):
        container = self._container_name(client_id)
        self.ssh.run_sudo_command(f"docker rm -f {shlex.quote(container)} || true")
        return {'status': 'success'}

    def toggle_client(self, protocol, client_id, enable):
        """Stop/start a user's exit container. Disabling MUST stop it — the
        container runs with --restart unless-stopped and would otherwise keep
        serving traffic (and survive reboots), defeating ban/quota enforcement."""
        container = self._container_name(client_id)
        if enable:
            self.ssh.run_sudo_command(f"docker start {shlex.quote(container)} || true")
        else:
            self.ssh.run_sudo_command(f"docker stop {shlex.quote(container)} || true")
        return {'status': 'success', 'enabled': bool(enable)}

    def get_client_config(self, protocol, client_id, host=None, port=None):
        """OpenFlux config is app instructions built from the stored doc URL, so
        callers should render from data.json. Kept for interface compatibility."""
        status = self.connection_status(client_id)
        state = 'running' if status['running'] else 'stopped'
        return f"OpenFlux exit node '{client_id}' is {state}. Use the OpenFlux app with your Yandex doc URL."

    def reconcile(self, active_client_ids, apply=True):
        """Remove orphan/zombie exit containers; return a report.
        - orphan: container whose client_id has no active connection record -> removed
        - down:   tracked container that is not Up (crashed/stopped)
        - running/seen: tracked/all container client_ids observed
        active_client_ids: client_id strings the panel still tracks.
        apply=False makes it a dry run (report only, no docker rm)."""
        active = set(str(c) for c in (active_client_ids or []))
        report = {'removed_orphans': [], 'down': [], 'running': [], 'seen': []}
        prefix = f'{self.CONTAINER_PREFIX}-'
        for c in self._list_client_containers():
            name = c['name']
            cid = name[len(prefix):] if name.startswith(prefix) else name
            report['seen'].append(cid)
            up = c['status'].startswith('Up')
            if cid not in active:
                if apply:
                    self.ssh.run_sudo_command(f"docker rm -f {shlex.quote(name)} || true")
                report['removed_orphans'].append(cid)
            elif not up:
                report['down'].append({'client_id': cid, 'name': name})
            else:
                report['running'].append(cid)
        return report

    def connection_status(self, client_id):
        container = self._container_name(client_id)
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{container}$ --format '{{{{.Status}}}}'"
        )
        return {'running': out.strip().startswith('Up'), 'container': container, 'status': out.strip()}

    # =============================================================== HELPERS
    @staticmethod
    def build_instructions(doc_url, transport='vyandex'):
        tab = {'vyandex': 'VOLGA', 'yandex': 'Yandex Docs', 'oneme': 'MAX'}.get(transport, 'VOLGA')
        return (
            "✅ Туннель заведён на ваш документ.\n\n"
            "Как подключиться:\n"
            "1. Установите приложение OpenFlux:\n"
            f"   iOS: {OPENFLUX_IOS_URL}\n"
            f"   Android: {OPENFLUX_ANDROID_URL}\n"
            f"2. Выберите вкладку транспорта: {tab}.\n"
            "3. Вставьте этот URL документа:\n"
            f"{doc_url}\n"
            "4. Включите мобильный интернет и нажмите Start VPN.\n\n"
            "⚠️ Важно:\n"
            "• На один документ — только ОДНО активное подключение (второе всё сломает).\n"
            "• Скорость очень низкая — это аварийный канал, не полноценный VPN.\n"
            "• Используйте только для критичного: Telegram, WhatsApp, мессенджеры.\n"
            "  Не для видео, загрузок и тяжёлых сайтов.\n"
            "• Документ должен оставаться публичным (доступ по ссылке — редактирование)."
        )
