"""
SSH Manager - manages SSH connections to VPN servers.
Replicates the ServerController logic from the AmneziaVPN client.

Connections can optionally be tunnelled through a jump host (bastion). Some
networks run DPI that lets the TCP handshake to port 22 complete and then kills
the session during the SSH banner / key exchange — from the client that looks
like `kex_exchange_identification: read: Operation timed out`. Relaying the
control SSH through a clean host outside that network is the way around it, so
every connection attempt here is either direct or a `direct-tcpip` channel
opened on a bastion.
"""

import paramiko
import io
import time
import logging
import threading
import socket

logger = logging.getLogger(__name__)
# Paramiko may emit noisy transport tracebacks during transient banner failures.
# We handle retries explicitly, so keep this logger quiet.
logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)


# How a server may be routed. 'fallback' tries direct first and only tunnels
# when the direct attempt fails; 'always' never touches the target directly.
JUMP_MODES = ('off', 'fallback', 'always')

# Timeouts for a normal (single-route) connection attempt.
FULL_TIMEOUTS = {'timeout': 20, 'banner_timeout': 45, 'auth_timeout': 30}
# Timeouts for a direct attempt that has a bastion queued up behind it. A DPI
# drop only shows up as a stalled banner read, so waiting out the full 45s
# banner timeout before falling back would make every operation unusably slow.
PROBE_TIMEOUTS = {'timeout': 8, 'banner_timeout': 10, 'auth_timeout': 15}
# Opening the direct-tcpip channel on the bastion.
JUMP_CHANNEL_TIMEOUT = 20
# Long installs leave the tunnel idle for minutes; keep the bastion hop warm.
JUMP_KEEPALIVE = 30

# How long a learned "this host only answers through the bastion" hint stays
# valid. Every panel operation builds a fresh SSHManager, so without this hint
# each one would re-pay the direct-connect timeout before falling back.
ROUTE_HINT_TTL = 600.0

# Concurrent reachability probes allowed through a bastion at once. OpenSSH
# defaults to MaxStartups 10:30:100, and every probe is a fresh login.
MAX_CONCURRENT_JUMP_PROBES = 4
_probe_slots = threading.BoundedSemaphore(MAX_CONCURRENT_JUMP_PROBES)


class JumpHostError(Exception):
    """The bastion hop itself failed (auth, unreachable, channel refused).

    Kept distinct from target-side failures so the caller can tell "the relay
    is broken" from "the server is broken", and so a bad bastion never aborts
    a direct attempt that might still work.
    """


def load_private_key(private_key):
    """Parse a PEM private key, trying each type paramiko supports."""
    key_file = io.StringIO(private_key)
    try:
        return paramiko.RSAKey.from_private_key(key_file)
    except paramiko.ssh_exception.SSHException:
        key_file.seek(0)
        try:
            return paramiko.Ed25519Key.from_private_key(key_file)
        except paramiko.ssh_exception.SSHException:
            key_file.seek(0)
            return paramiko.ECDSAKey.from_private_key(key_file)


def normalize_jump_config(raw):
    """Coerce a raw jump-host dict into canonical form, or None if unusable.

    A block without a host is not a bastion, no matter what else it carries.
    """
    if not isinstance(raw, dict):
        return None
    host = str(raw.get('host') or '').strip()
    if not host:
        return None
    try:
        port = int(raw.get('port') or 22)
    except (TypeError, ValueError):
        port = 22
    return {
        'host': host,
        'port': port,
        'username': str(raw.get('username') or '').strip() or 'root',
        'password': raw.get('password') or '',
        'private_key': raw.get('private_key') or '',
    }


def normalize_jump_mode(raw, default='off'):
    mode = str(raw or '').strip().lower()
    return mode if mode in JUMP_MODES else default


def resolve_jump(server, settings=None):
    """Work out which bastion (if any) a server record should be reached through.

    The global default lives in `settings['ssh_jump']`; a server may override it
    with its own `ssh_jump` block. An override naming its own `host` replaces
    the global bastion wholesale — mixing one bastion's address with another's
    credentials is never what anybody means. An override that only sets `mode`
    (or leaves it at 'inherit') keeps using the global bastion, which is how a
    single server opts in or out of the shared default.

    Returns (jump_config_or_None, mode).
    """
    settings = settings if isinstance(settings, dict) else {}
    server = server if isinstance(server, dict) else {}

    global_raw = settings.get('ssh_jump')
    global_raw = global_raw if isinstance(global_raw, dict) else {}
    override = server.get('ssh_jump')
    override = override if isinstance(override, dict) else {}

    mode = normalize_jump_mode(override.get('mode'), '')
    if not mode:
        # 'inherit' / unset: take the global setting, which the master switch
        # can shut off for every server at once.
        mode = normalize_jump_mode(global_raw.get('mode'), 'fallback')
        if not global_raw.get('enabled'):
            mode = 'off'

    if mode == 'off':
        return None, 'off'

    # A per-server 'always'/'fallback' can point at the global bastion even
    # while the global master switch is off — that is the per-server opt-in.
    config = normalize_jump_config(override) or normalize_jump_config(global_raw)
    if config is None:
        return None, 'off'
    return config, mode


def server_ssh_host(server):
    """The address the panel should SSH to for a server record.

    `ssh_address` wins over `host` so the control connection can be pinned to a
    literal IP while `host` stays the name users see (and the name the VPN
    endpoint is published under). DNS answers for these hosts are not always
    trustworthy on the panel's network.
    """
    if not isinstance(server, dict):
        return ''
    return str(server.get('ssh_address') or '').strip() or server.get('host', '')


def _close_quietly(client):
    if not client:
        return
    try:
        client.close()
    except Exception:
        pass


def _is_transient(error):
    """True for failures that are worth retrying on the same route."""
    msg = str(error).lower()
    if not isinstance(
        error,
        (
            paramiko.ssh_exception.SSHException,
            socket.timeout,
            TimeoutError,
            EOFError,
        ),
    ):
        return False
    return (
        'no existing session' in msg
        or 'error reading ssh protocol banner' in msg
        or 'ssh protocol banner' in msg
        or 'timed out' in msg
        or isinstance(error, (socket.timeout, TimeoutError, EOFError))
    )


def open_jump_channel(jump, host, port, timeouts=None, channel_timeout=JUMP_CHANNEL_TIMEOUT):
    """Open a direct-tcpip channel to (host, port) through the bastion.

    Returns (bastion_client, channel); the caller owns both and must close the
    bastion once the channel is done. The target address is handed to the
    bastion as a string, so when it is a literal IP no DNS lookup happens on
    either side of the hop.
    """
    bastion = paramiko.SSHClient()
    bastion.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kwargs = {
        'hostname': jump['host'],
        'port': jump['port'],
        'username': jump['username'],
        'allow_agent': False,
        'look_for_keys': False,
    }
    kwargs.update(timeouts or FULL_TIMEOUTS)

    try:
        if jump.get('private_key'):
            kwargs['pkey'] = load_private_key(jump['private_key'])
        elif jump.get('password'):
            kwargs['password'] = jump['password']

        bastion.connect(**kwargs)
        transport = bastion.get_transport()
        if transport is None:
            raise paramiko.ssh_exception.SSHException('jump host transport unavailable')
        transport.set_keepalive(JUMP_KEEPALIVE)
        channel = transport.open_channel(
            'direct-tcpip', (host, port), ('127.0.0.1', 0), timeout=channel_timeout
        )
    except Exception as e:
        _close_quietly(bastion)
        raise JumpHostError(
            f"jump host {jump['username']}@{jump['host']}:{jump['port']}: {e}"
        ) from e

    return bastion, channel


def probe_via_jump(jump, host, port, timeout=8):
    """Time how long the bastion takes to reach (host, port); return milliseconds.

    Deliberately does not take the global operation slot - it opens and closes a
    channel without running anything, so it cannot interleave badly with a real
    operation, and reachability checks should never queue behind an install.

    It does take `_probe_slots`: a dashboard pings every card at once, and each
    probe is a full SSH login, so an unthrottled fan-out trips the bastion's
    MaxStartups and reads back as "server offline".
    """
    timeouts = {'timeout': timeout, 'banner_timeout': timeout, 'auth_timeout': timeout}
    with _probe_slots:
        started = time.monotonic()
        bastion, channel = open_jump_channel(jump, host, port, timeouts, channel_timeout=timeout)
        try:
            return round((time.monotonic() - started) * 1000)
        finally:
            try:
                channel.close()
            except Exception:
                pass
            _close_quietly(bastion)


class SSHManager:
    """Manages SSH connections and command execution on remote servers."""

    _operation_lock = threading.Lock()
    _state_lock = threading.Lock()
    _waiting_count = 0
    _active_host = None
    # (host, port) -> monotonic deadline until which we prefer the bastion.
    _route_hints = {}
    # Global jump settings for callers that have no `settings` dict at hand
    # (the Telegram bot, background jobs). Installed by the app on startup and
    # whenever settings are saved.
    _default_settings = {}

    def __init__(self, host, port, username, password=None, private_key=None,
                 jump=None, jump_mode='off', public_host=None):
        self.host = host
        # The address clients reach this server on, which is not always the one
        # we SSH to: `ssh_address` can pin management traffic to a literal IP.
        # Managers that publish an endpoint must use this, never `host`.
        self.public_host = public_host or host
        self.port = int(port)
        self.username = username
        self.password = password
        self.private_key = private_key
        self.jump = normalize_jump_config(jump)
        self.jump_mode = normalize_jump_mode(jump_mode) if self.jump else 'off'
        self.client = None
        # Bastion client backing the current connection; it has to stay open
        # for as long as the tunnelled session lives.
        self._jump_client = None
        self.active_jump = None
        self._is_root = (username == 'root')
        self._slot_acquired = False
        self.waited_for_slot = False
        self.wait_time_seconds = 0.0

    @classmethod
    def set_default_settings(cls, settings):
        """Install the panel settings used to resolve jump hosts by default."""
        with cls._state_lock:
            cls._default_settings = settings if isinstance(settings, dict) else {}

    @classmethod
    def for_server(cls, server, settings=None):
        """Build a manager for a panel server record, jump host included."""
        if settings is None:
            with cls._state_lock:
                settings = cls._default_settings
        jump, jump_mode = resolve_jump(server, settings)
        return cls(
            host=server_ssh_host(server),
            port=server.get('ssh_port', 22) or 22,
            username=server.get('username', 'root'),
            password=server.get('password'),
            private_key=server.get('private_key'),
            jump=jump,
            jump_mode=jump_mode,
            public_host=server.get('host', ''),
        )

    @classmethod
    def get_queue_state(cls):
        """Return current global SSH queue state."""
        with cls._state_lock:
            return {
                'busy': cls._operation_lock.locked(),
                'waiting': cls._waiting_count,
                'active_host': cls._active_host,
            }

    @classmethod
    def _prefers_jump(cls, host, port):
        with cls._state_lock:
            expires = cls._route_hints.get((host, port))
            if expires is None:
                return False
            if expires <= time.monotonic():
                cls._route_hints.pop((host, port), None)
                return False
            return True

    @classmethod
    def _remember_route(cls, host, port, used_jump):
        with cls._state_lock:
            if used_jump:
                cls._route_hints[(host, port)] = time.monotonic() + ROUTE_HINT_TTL
            else:
                cls._route_hints.pop((host, port), None)

    @classmethod
    def forget_routes(cls):
        """Drop learned routing hints (after a settings or server edit)."""
        with cls._state_lock:
            cls._route_hints.clear()

    def _acquire_operation_slot(self):
        """Acquire global operation slot so SSH operations execute strictly one by one."""
        started = time.monotonic()

        if SSHManager._operation_lock.acquire(blocking=False):
            self._slot_acquired = True
            self.waited_for_slot = False
            self.wait_time_seconds = 0.0
            with SSHManager._state_lock:
                SSHManager._active_host = self.host
            return

        with SSHManager._state_lock:
            SSHManager._waiting_count += 1
            queue_pos = SSHManager._waiting_count

        self.waited_for_slot = True
        logger.info(
            "SSH busy: queued operation for %s@%s (position %s)",
            self.username,
            self.host,
            queue_pos,
        )

        SSHManager._operation_lock.acquire()
        self._slot_acquired = True
        self.wait_time_seconds = max(0.0, time.monotonic() - started)

        with SSHManager._state_lock:
            if SSHManager._waiting_count > 0:
                SSHManager._waiting_count -= 1
            SSHManager._active_host = self.host

        logger.info(
            "SSH queue: started operation for %s@%s after %.2fs wait",
            self.username,
            self.host,
            self.wait_time_seconds,
        )

    def _release_operation_slot(self):
        if not self._slot_acquired:
            return

        with SSHManager._state_lock:
            SSHManager._active_host = None

        self._slot_acquired = False
        self.waited_for_slot = False
        self.wait_time_seconds = 0.0
        SSHManager._operation_lock.release()

    def describe_route(self):
        """Human-readable description of how this connection is routed."""
        target = f"{self.username}@{self.host}:{self.port}"
        jump = self.active_jump or (self.jump if self.jump_mode == 'always' else None)
        if not jump:
            return target
        return f"{target} via {jump['username']}@{jump['host']}:{jump['port']}"

    def _plan_routes(self):
        """Ordered routes to try. None means direct, a dict means via that bastion."""
        if not self.jump or self.jump_mode == 'off':
            return [None]
        if self.jump_mode == 'always':
            return [self.jump]
        # Fallback mode: direct first, unless we recently learned this host only
        # answers through the bastion.
        if self._prefers_jump(self.host, self.port):
            return [self.jump, None]
        return [None, self.jump]

    def _auth_kwargs(self):
        """Auth material for the target host."""
        if self.private_key:
            return {'pkey': load_private_key(self.private_key)}
        if self.password:
            return {'password': self.password}
        return {}

    def _open_jump_channel(self, jump):
        return open_jump_channel(jump, self.host, self.port)

    def _connect_once(self, jump, auth_kwargs, timeouts):
        """One connection attempt over one route. Raises on failure."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        bastion = None

        kwargs = {
            'hostname': self.host,
            'port': self.port,
            'username': self.username,
            'allow_agent': False,
            'look_for_keys': False,
        }
        kwargs.update(timeouts)
        kwargs.update(auth_kwargs)

        try:
            if jump:
                bastion, kwargs['sock'] = self._open_jump_channel(jump)
                # With `sock` supplied paramiko does not create the socket, so
                # `timeout` no longer governs setup; banner/auth timeouts do.
            client.connect(**kwargs)
        except Exception:
            _close_quietly(client)
            _close_quietly(bastion)
            raise

        self.client = client
        self._jump_client = bastion
        self.active_jump = jump

    def connect(self):
        """Establish SSH connection to the server, tunnelling if configured."""
        self._acquire_operation_slot()

        try:
            auth_kwargs = self._auth_kwargs()
        except Exception:
            # A malformed key must not leave the global slot held.
            self.disconnect()
            raise

        routes = self._plan_routes()
        last_error = None

        for route_index, jump in enumerate(routes):
            has_fallback = route_index + 1 < len(routes)
            timeouts = PROBE_TIMEOUTS if (jump is None and has_fallback) else FULL_TIMEOUTS
            # A single route keeps the original resilience. With another route
            # waiting, that route is the retry - re-dialling one DPI is eating
            # only doubles the wait before we get to the one that works.
            if len(routes) == 1:
                max_attempts = 4
            elif has_fallback:
                max_attempts = 1
            else:
                max_attempts = 2

            for attempt in range(1, max_attempts + 1):
                try:
                    self._connect_once(jump, auth_kwargs, timeouts)
                    self._remember_route(self.host, self.port, used_jump=bool(jump))
                    if jump:
                        logger.info(
                            "SSH connected to %s@%s:%s through jump host %s@%s:%s",
                            self.username, self.host, self.port,
                            jump['username'], jump['host'], jump['port'],
                        )
                    return True
                except paramiko.ssh_exception.AuthenticationException:
                    # Target credentials are wrong; no route fixes that.
                    self.disconnect()
                    raise
                except Exception as e:
                    last_error = e
                    if attempt < max_attempts and _is_transient(e):
                        logger.warning(
                            "SSH transient connect error for %s@%s (attempt %s/%s): %s",
                            self.username,
                            self.host,
                            attempt,
                            max_attempts,
                            e,
                        )
                        time.sleep(0.5 * (2 ** (attempt - 1)))
                        continue
                    break

            if has_fallback:
                next_jump = routes[route_index + 1]
                logger.warning(
                    "SSH route %s failed for %s@%s:%s (%s) - retrying %s",
                    'via jump host' if jump else 'direct',
                    self.username, self.host, self.port, last_error,
                    'via jump host' if next_jump else 'directly',
                )

        # If connection fails, release slot immediately so queue does not stall.
        self.disconnect()
        raise last_error

    def disconnect(self):
        """Close SSH connection (and the bastion hop backing it, if any)."""
        try:
            _close_quietly(self.client)
            _close_quietly(self._jump_client)
            self.client = None
            self._jump_client = None
            self.active_jump = None
        finally:
            self._release_operation_slot()

    def run_command(self, command, timeout=60):
        """Execute command on remote server."""
        if not self.client:
            raise ConnectionError("Not connected to server")

        logger.info(f"Running command: {command[:100]}...")
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        
        # Crucial: set timeout on the channel to prevent hanging indefinitely
        stdout.channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)
        
        try:
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace').strip()
            err = stderr.read().decode('utf-8', errors='replace').strip()
        except Exception as e:
            logger.error(f"Command timed out or failed to read: {e}")
            out, err, exit_code = "", str(e), -1

        if exit_code != 0:
            logger.warning(f"Command exited with code {exit_code}: {err}")

        return out, err, exit_code

    def _sudo_prefix(self):
        """Get the sudo command prefix with password handling."""
        if self._is_root:
            return ''
        if self.password:
            # Use sudo -S to read password from stdin
            escaped_pass = self.password.replace("'", "'\\''")
            return f"echo '{escaped_pass}' | sudo -S "
        return 'sudo '

    def run_sudo_command(self, command, timeout=60):
        """
        Execute command with sudo, automatically handling password.
        Strips 'sudo ' from the beginning of command if present,
        and re-adds it with password piping.
        """
        # Remove existing sudo prefix if present
        clean_cmd = command
        if clean_cmd.strip().startswith('sudo '):
            clean_cmd = clean_cmd.strip()[5:]

        if self._is_root:
            return self.run_command(clean_cmd, timeout=timeout)

        if self.password:
            escaped_pass = self.password.replace("'", "'\\''")
            # Pipe password directly to sudo -S, preserving original command quoting
            # 2>/dev/null on echo suppresses '[sudo] password for...' prompt noise
            full_cmd = f"echo '{escaped_pass}' | sudo -S -p '' {clean_cmd}"
        else:
            full_cmd = f"sudo {clean_cmd}"

        return self.run_command(full_cmd, timeout=timeout)

    def run_sudo_script(self, script, timeout=120):
        """
        Execute a multi-line script with sudo/root privileges.
        Writes script to /tmp via SFTP, then runs with sudo bash.
        """
        if self._is_root:
            return self.run_script(script, timeout=timeout)

        # Write script to temp file via SFTP (avoids heredoc/pipe conflicts)
        import hashlib
        script_hash = hashlib.md5(script.encode()).hexdigest()[:8]
        tmp_script = f"/tmp/_amnz_script_{script_hash}.sh"
        self.upload_file(script, tmp_script)

        # Run with sudo
        if self.password:
            escaped_pass = self.password.replace("'", "'\\''")
            full_cmd = f"echo '{escaped_pass}' | sudo -S -p '' bash {tmp_script}; rm -f {tmp_script}"
        else:
            full_cmd = f"sudo bash {tmp_script}; rm -f {tmp_script}"

        return self.run_command(full_cmd, timeout=timeout)

    def run_script(self, script, timeout=120):
        """Execute a multi-line script on remote server."""
        return self.run_command(script, timeout=timeout)

    def upload_file(self, content, remote_path):
        """Upload text content to a remote file via SFTP."""
        if not self.client:
            raise ConnectionError("Not connected to server")

        # Normalize line endings (Windows CRLF -> Unix LF)
        content = content.replace('\r\n', '\n')

        sftp = self.client.open_sftp()
        try:
            with sftp.file(remote_path, 'w') as f:
                f.write(content)
        finally:
            sftp.close()

    def upload_file_sudo(self, content, remote_path):
        """
        Upload text content to a remote file that requires root access.
        Uses SFTP to write to /tmp, then sudo mv to the target path.
        Also normalizes line endings to Unix-style (LF).
        """
        if not self.client:
            raise ConnectionError("Not connected to server")

        # Normalize line endings (Windows CRLF -> Unix LF)
        content = content.replace('\r\n', '\n')

        # Write to temp file via SFTP (no sudo needed for /tmp)
        import hashlib
        tmp_name = f"/tmp/_amnz_{hashlib.md5(remote_path.encode()).hexdigest()[:8]}"
        self.upload_file(content, tmp_name)

        # Move to target with sudo
        self.run_sudo_command(f"mv {tmp_name} {remote_path}")
        self.run_sudo_command(f"chmod 644 {remote_path}")
        return True

    def download_file(self, remote_path):
        """Download text content from a remote file."""
        if not self.client:
            raise ConnectionError("Not connected to server")

        sftp = self.client.open_sftp()
        try:
            with sftp.file(remote_path, 'r') as f:
                return f.read().decode('utf-8', errors='replace')
        finally:
            sftp.close()

    def file_exists(self, remote_path):
        """Check if a remote file exists."""
        if not self.client:
            raise ConnectionError("Not connected to server")

        sftp = self.client.open_sftp()
        try:
            sftp.stat(remote_path)
            return True
        except FileNotFoundError:
            return False
        finally:
            sftp.close()

    def test_connection(self):
        """Test SSH connection and return server info."""
        out, err, code = self.run_command("uname -sr && cat /etc/os-release 2>/dev/null | head -2")
        return out

    def write_file(self, remote_path, content):
        """Write content to a remote file with sudo."""
        return self.upload_file_sudo(content, remote_path)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
