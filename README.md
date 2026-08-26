# Amnezia Web Panel

A modern, high-performance web interface for managing **AmneziaWG**, **Classic WireGuard**, **Xray (XTLS-Reality)**, **Telemt (Telegram MTProxy)**, **Cloudflare WARP**, **AmneziaDNS**, **AdGuard Home**, **SOCKS5**, and **NGINX + Let's Encrypt** services on remote Ubuntu servers — from a single dashboard. Designed to provide a premium user experience with robust administrative capabilities.

> ### 🔄 Compatibility with Official Amnezia Client
> 
> This panel is fully compatible with the official **Amnezia** applications!
> 
> **How to connect an existing server:**
> 1. Add your pre-configured server by entering its **IP address**, **login** and **password**
> 2. Go to the "Added Servers" section
> 3. Wait for the automatic server verification
> 4. The panel will automatically detect:
>    - ✅ Installed protocols
>    - ✅ Existing users
>    - ✅ Current configuration
>
> ⚡ **After verification, you can manage the server directly from the panel!**

## ⚠️ Legal Notice

> **This project is created solely for educational and research purposes.**
>
> **This project has never been intended for use in jurisdictions where the technologies employed are prohibited.** The author bears no responsibility for any unlawful use of this software.

**This project merely adds an abstraction layer for managing publicly available applications.** All applications belong to their respective owners. This project does not claim ownership over, nor does it modify, any third-party applications.

The use of traffic obfuscation tools may violate the laws of your country. Only use this software for lawful purposes, such as:

- **Penetration testing and security research**
- **CTF (Capture The Flag) competitions**
- **Academic and scientific research**
- **Testing and securing your own networks**
- **Improving defensive security measures**
- **Educational training in cybersecurity**

> **Nothing in this project constitutes an incitement to violate any applicable laws.**
![Servers Dashboard](https://raw.githubusercontent.com/PRVTPRO/Amnezia-Web-Panel/refs/heads/main/screen/panel1.png)


### Additional Sections

<details>
<summary><b>👥 Users Management</b> (click to expand)</summary>
<br>
User management interface with permissions and access controls:

![Users Management](https://github.com/PRVTPRO/Amnezia-Web-Panel/blob/main/screen/panel1-2.png)
</details>

<details>
<summary><b>⚙️ System Settings</b> (click to expand)</summary>
<br>
Configuration panel for system parameters and preferences:

![Settings Panel](https://github.com/PRVTPRO/Amnezia-Web-Panel/blob/main/screen/panel1-3.png)
</details>

## 🚀 Key Features

*   **⚡ VPN Protocols**:
    *   **AmneziaWG (AWG / AWG 2.0 / AWG Legacy)**: Advanced WireGuard-based protocol with S3/S4 obfuscation to bypass deep packet inspection (DPI). Three coexisting variants — modern AWG 2.0 with full junk-packet masking, and a legacy variant for older clients.
    *   **Classic WireGuard**: Standard, high-performance WireGuard protocol for unmatched speed and broad device compatibility with traffic monitoring support.
    *   **Xray (XTLS-Reality)**: Stealthy protocol that masks VPN traffic as standard HTTPS browsing. Pinned to **Xray-core v26.x**; transparently reads both the **panel layout** (`meta.json` + `clientsTable.json`) and the **native Amnezia client layout** (`xray_*.key` files + `clientsTable`), so a node first installed via the official mobile/desktop app can be attached to the panel without re-installation.
    *   **Telemt (Telegram MTProxy)**: High-performance Telegram MTProxy with TLS emulation and comprehensive management (quotas, IP limits, real-time session tracking). Robust install path that auto-configures Docker's official apt/yum repository when needed.
    *   **Cloudflare WARP**: Add and manage WARP-powered connectivity from the panel for routing and network flexibility.
*   **🛠 Services**:
    *   **AmneziaDNS**: Internal DNS resolver on a private docker network (`amnezia-dns-net`, IP `172.29.172.254`) to prevent DNS leaks and blockings.
    *   **AdGuard Home**: DNS-based ad blocker with a web admin UI. Two install modes: **Replace AmneziaDNS** (takes its IP, all VPN clients use AdGuard immediately) or **Side-by-side** (parallel deployment on `172.29.172.253`, web UI accessible only over the VPN by default). Optional opt-in checkboxes to expose the web UI / DoT / DoH on the host.
    *   **SOCKS5 Proxy**: Single-account 3proxy-based SOCKS5 server modelled after the official Amnezia client. Auto-generated 16-character password on install, port and credentials editable later from the panel without re-install.
    *   **NGINX + Let's Encrypt**: Reverse-proxy and HTTPS automation with certificate management for secure public endpoints.
*   **⚙️ Core Server Management**:
    *   **Add / Edit / Delete / Reorder** server entries — drag-and-drop reorder updates `server_id` references in saved connections automatically.
    *   **Live ping indicator** next to each server name — non-blocking TCP-connect probe to the SSH port, runs on the asyncio loop in parallel for all servers.
    *   **SSH jump host (bastion)** — relay the management SSH through a clean intermediate server when the direct route to port 22 is filtered. Global default plus per-server override, and a fallback mode that only tunnels after a direct attempt fails. See [SSH Jump Host](#-ssh-jump-host-bastion).
    *   **Clear server** wipes every Amnezia-related container, image and `/opt/amnezia` directory in a single sudo script — works for any current or future `amnezia-*` protocol.
    *   **Reboot** the server directly from the UI.
    *   Strictly concurrent protocol status polling — all supported protocols/services checked in parallel for immediate feedback.
    *   **Asynchronous Processing**: Resilient, non-blocking background architecture prevents the UI panel from freezing, even if remote endpoints hang.
*   **🧩 Marketplace & Templates**:
    *   Market templates provide quick presets for installing and configuring supported protocols and services.
    *   Multi-protocol management lets you run and control multiple protocol instances on the same server.
*   **🌐 Internationalization (i18n)**:
    *   Full support for **English**, **Russian**, **French**, **Chinese**, and **Persian**.
    *   Native **RTL (Right-to-Left)** support for Persian language.
*   **👥 Advanced User Management**:
    *   Role-based access (Admin, Support, Regular User).
    *   Traffic limits, status monitoring, and account expiration.
    *   One-click user enabling/disabling.
*   **🎨 Premium UI/UX**:
    *   Stunning glassmorphism design.
    *   Dynamic **Dark/Light** mode transition.
    *   Fully responsive for mobile and desktop.
*   **🤖 Telegram Bot Integration**:
    *   Notify users about new connections or limits.
    *   Integrated management via Telegram commands.
    *   Admin-role workflows for managing servers, protocols, users, and connections directly from Telegram.
*   **🔄 Built-in Update Checker**:
    *   View your current panel version directly in Settings.
    *   One-click check for fresh GitHub releases to stay up to date.
*   **📤 Data Interoperability**:
    *   **Remnawave Sync**: Automatically import and sync users from Remnawave.
    *   **Simple Backup**: Effortless JSON-based export and restore of all panel data.
    *   **Backup / Migrate protocols (Alpha)**: Move protocol configurations between nodes for maintenance, recovery, and migration workflows.
*   **🔗 Public Sharing**:
    *   Generate password-protected links for users to download their configurations without panel access.
*   **🌍 One-click Public Tunnels**:
    *   Open the local panel to the internet from `/settings` using **Cloudflare Quick Tunnel** or **ngrok**.
    *   Shows the local server URL, installation state, running state, and issued public HTTPS URLs directly in the UI.
    *   Supports one-click install, enable, stop, and delete for panel-managed tunnel binaries.
    *   Persists tunnel PID/public URL state across panel restarts and can detect already running tunnel processes.
    *   Works on Windows, Linux, and Docker-friendly environments; `TUNNEL_BIN_DIR` and `TUNNEL_STATE_FILE` can override binary/state locations.
*   **🔑 API Tokens for External Integrations**:
    *   Issue bearer tokens from `/settings` for CI bots, monitoring, or any third-party service.
    *   Panel never stores the raw token — only its SHA-256 hash. The full value is shown **once** at creation; lose it and you must rotate.
    *   Tokens inherit the role of the admin who created them and are revoked automatically if that user is disabled or demoted.
    *   Send `Authorization: Bearer <token>` with any admin endpoint — every endpoint that accepts a session also accepts a token, no other changes.

## 💡 Need Additional Functionality?

If you require any custom features not currently available in the panel, **let us know – we'll implement them quickly!** 

* **Database Support**: PostgreSQL, MySQL/MariaDB, SQLite, Oracle, and MS SQL Server
* **In-Panel File Editor**: Edit configuration files inside containers directly from the web interface
* **Advanced backup automation**: Scheduled backups, external storage, and richer recovery workflows
* **Advanced protocol migration**: Extended migration tooling for complex multi-node setups
* **Xray Self-Steal Mode**: Advanced Xray configuration with self-steal functionality
* **And much more!**

**Or better yet, contribute!**


## 🏗 Prerequisites

*   **Python 3.10+**
*   Target servers: **Ubuntu 20.04/22.04/24.04** (Architecture: x86_64 or ARM64).
*   SSH access to target servers (Password or Private Key).

## 📦 Installation 

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/PRVTPRO/Amnezia-Web-Panel.git
    cd Amnezia-Web-Panel
    ```

2.  **Set up Virtual Environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
## 🚀 Getting Started

Launch the application:

```bash
python app.py
```

The panel will be accessible at `http://localhost:5000`.

## 📦 Installation Method 2

Download and run the executable file for your system.
```
Windows
Linux
Mac
```

## 🐳 Docker Image

https://hub.docker.com/r/prvtpro/amnezia-panel


### Initial Login
*   **Username**: `admin`
*   **Password**: `admin`
> [!IMPORTANT]  
> Secure your panel by changing the default password in the **Users** section immediately after first login.

## 🔧 Project Details

### API Documentation

The project includes self-documenting API endpoints, organised into clear tag groups:

*   **Swagger UI**: `/docs`
*   **ReDoc**: `/redoc` (pinned to a stable bundle, Google Fonts disabled — works on networks where they're blocked)

Routes are grouped in the docs as:

| Group | Purpose |
| --- | --- |
| **System Templates** | HTML pages served to browsers (login, server detail, settings, /share). Not part of the JSON API. |
| **Authentication** | Login, captcha, session lifecycle. |
| **Servers** | Server inventory & host-level operations (add/edit/delete, ping, reorder, reboot, clear, stats). |
| **Protocols** | Install / uninstall / container / raw-config editing for every protocol & service on a server. |
| **Connections** | Per-protocol VPN client connections (CRUD, enable/disable, fetch config). |
| **Users** | Panel user accounts and the connections assigned to them. |
| **Self-service** | Endpoints called by a regular user for their own data (`/api/my/*`). |
| **Sharing** | Public, token-protected configuration sharing — no panel session required. |
| **Settings** | Panel-wide settings, Telegram bot, Remnawave sync, JSON backup/restore. |
| **API Tokens** | Create and revoke bearer tokens for external integrations. |

**Authentication for external integrations** — both session cookies and `Authorization: Bearer <token>` are accepted on every admin endpoint. Example:

```bash
TOKEN="awp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# List panel users
curl -H "Authorization: Bearer $TOKEN" http://your-panel:5000/api/users

# Add a server
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"host":"1.2.3.4","username":"root","password":"...","name":"new-srv"}' \
  http://your-panel:5000/api/servers/add

# Cheap reachability probe for monitoring
curl -H "Authorization: Bearer $TOKEN" http://your-panel:5000/api/servers/0/ping
```

### 🔗 SSH Jump Host (bastion)

Some networks let the TCP handshake to port 22 complete and then kill the session during the
SSH banner / key exchange — the client sees `kex_exchange_identification: read: Operation timed out`
while the server itself is healthy and its VPN port keeps working. The panel can route its
management SSH through a clean intermediate host to get around that.

Configure the default bastion in **Settings → SSH Jump Host**:

| Field | Meaning |
| --- | --- |
| **Use a jump host by default** | Master switch. Off means every server connects directly unless it overrides the setting itself. |
| **Routing** | `Direct first, jump host on failure` probes directly with a short timeout and tunnels only when that fails. `Always through the jump host` never dials the target directly. |
| **Host / port / user** | The bastion's SSH endpoint. |
| **Password / SSH key** | Bastion credentials. They are never sent back to the browser — leave the field blank to keep what is stored. |
| **Test jump host** | Logs into the bastion and, optionally, checks that it can open a tunnel to a chosen server. |

Each server can depart from the default in its own **Edit server** dialog:

*   **Routing** — `Use the global setting` (default), `Never`, `Direct first…`, or `Always…`. A server can
    opt into the bastion even while the global switch is off, and opt out while it is on.
*   **Jump host address** — leave empty to use the global bastion and change only the routing. Filling it in
    replaces the bastion wholesale for that server (address *and* credentials together).
*   **SSH address** — an optional literal IP the panel dials for management instead of the host name, so the
    control connection does not depend on DNS. The host name is still what VPN clients get in their configs.
    When tunnelling, the address is resolved by the bastion, not by the panel.

Behaviour worth knowing:

*   In fallback mode the direct probe uses a short banner timeout (~10 s), so a filtered host costs one probe
    rather than the full 45 s before the tunnel is tried.
*   After a connection succeeds through the bastion, the panel remembers that route for that host for 10
    minutes and dials the bastion first, instead of re-paying the direct timeout on every operation. A later
    direct success clears the hint.
*   The bastion connection is pooled: one SSH login carries as many tunnels as needed, and concurrent work
    waits for that single login rather than each opening its own. This matters because SSH hardening usually
    rate-limits new connections — `ufw limit ssh` drops the sixth from one source inside 30 seconds, which a
    login-per-operation design exceeds on a single dashboard refresh. Idle logins are closed after 5 minutes,
    and editing the jump host or a server drops the pool so nothing keeps using the old credentials.
*   Wrong credentials on the target abort immediately — no route makes a bad password work. A broken bastion
    still lets the direct route be tried.
*   The ping indicator shows `⛓` when a server answered through the bastion.

Stored under `settings.ssh_jump` in `data.json`, with per-server overrides in each server's `ssh_jump` and
`ssh_address` keys. `POST /api/settings/save` leaves `ssh_jump` untouched when the field is omitted, so older
clients and scripted saves cannot wipe the bastion address.

### Technology Stack
*   **Backend**: FastAPI (Python), `asyncio` for concurrent SSH/probe work
*   **Frontend**: Vanilla JS, Jinja2, Custom CSS (Glassmorphism, full set of CSS animations for promo blocks)
*   **Database**: Local JSON storage (`data.json`) with an `asyncio.Lock` for thread-safe writes
*   **SSH Engine**: Paramiko

### Project Structure

```
web-panel/
├── app.py                    # FastAPI entry point + all routes
├── telegram_bot.py           # Optional Telegram bot integration
├── managers/                 # Protocol & service managers (one file per protocol)
│   ├── ssh_manager.py        # SSH abstraction (Paramiko wrapper)
│   ├── awg_manager.py        # AmneziaWG / AWG 2.0 / AWG Legacy
│   ├── wireguard_manager.py  # Classic WireGuard
│   ├── xray_manager.py       # Xray-core (VLESS-Reality)
│   ├── telemt_manager.py     # Telegram MTProxy
│   ├── dns_manager.py        # AmneziaDNS (Unbound)
│   ├── adguard_manager.py    # AdGuard Home
│   └── socks5_manager.py     # 3proxy-based SOCKS5
├── static/                   # CSS / favicon / vendored JS
├── templates/                # Jinja2 templates
├── translations/             # en / ru / fr / zh / fa
└── data.json                 # Panel state (servers, users, tokens, settings)
```

## 🛡 Security Recommendations

*   **Reverse Proxy**: It is highly recommended to run the panel behind Nginx/Apache with an SSL certificate.
*   **SSH Keys**: Use SSH keys rather than passwords for connecting to your VPN servers.
*   **Secret Key**: Set a custom `SECRET_KEY` environment variable for secure session management.
*   **API Tokens**: Treat each token like a password — store it in your integration's secret manager. Revoke it from `/settings` if it leaks or the integration is decommissioned. Rotate periodically; tokens inherit admin rights.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit Pull Requests or open Issues for feature requests and bug reports.

## 📄 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](../LICENSE) file for details.


---
*Built with ❤️ for the Amnezia community.*

