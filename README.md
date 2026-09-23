<div align="center">
  <img src="https://lh3.googleusercontent.com/83zgoeJAlOS95s4Z5fQNNtWK5QJngsEWDMQRGeYuMKkABGDbMEoeeFMyqvEpzKBh1krBHA-0Qr8ILCmSKD3egg" width="150" alt="RustProxy Logo" />
  <h1>RustProxy</h1>
  <p><b>Reverse SOCKS5 Tunnel Server and Client</b></p>
  <a href="https://play.google.com/store/apps/details?id=com.barissenel.rustproxy"><img src="https://img.shields.io/badge/Google_Play-Get_it_on_Play_Store-green?logo=google-play&style=for-the-badge" alt="Get it on Google Play" /></a>
</div>

---

RustProxy is a reverse proxy tunneling tool. It allows Android phones, PCs, or IoT devices behind strict firewalls to expose their internet connection as a SOCKS5 proxy to the public internet via a central server.

## Features

* **Reverse Tunneling:** Connect your phones or PCs to your public server to bypass restrictions without needing router port forwarding.
* **Web Dashboard:** A built-in web GUI hosted on your server to manage active connections, copy proxy details, and block IPs.
* **Persistent Proxies:** Your SOCKS5 proxies stay online even if your phone momentarily drops the connection.
* **QR Easy Connect:** Link the Android App to the server instantly by scanning a QR code from the Web Dashboard.
* **Remote IP Rotation (Android):** Trigger Airplane Mode to remotely rotate your phone's cellular IP address directly from the Web Dashboard.

---

## Getting Started

### 1. Download the Server
Download the latest pre-compiled server executable for Linux or Windows from the [Releases page](../../releases).

### 2. Run the Server
Upload the executable to your public VPS (like Ubuntu or Debian). Use a separate agent password and admin password:
```bash
./rust_proxy server -c 8080 -a 8081 -p "AgentPassword123" --admin-password "AdminPassword123"
```

- `-a 8081`: Dashboard/API port, bound only to `127.0.0.1`.
- `-c 8080`: This is the port your Android/PC agents connect to.
- `-p`: Agent password. `--admin-password`: dashboard and API password.

### 3. Open the Dashboard
Create an SSH tunnel from your workstation:
```
ssh -L 8081:127.0.0.1:8081 <user>@<YOUR_VPS_IP>
```
Then open `http://127.0.0.1:8081/` and enter the admin password.

## Production network layout

Keep the dashboard and raw TCP traffic on different hostnames:

| Purpose | Hostname | Cloudflare | Public port | Container port |
| --- | --- | --- | --- | --- |
| Dashboard | SSH tunnel or TLS reverse proxy | N/A | private | `127.0.0.1:8081` |
| Agent control | `agent.example.com` | DNS only | `18080` | `8080` |
| SOCKS proxies | `socks.example.com` | DNS only | `51300-51399` | `51300-51399` |

For Coolify, do not publish port 8081. Use a TLS reverse proxy that can reach the container's loopback API, or an SSH tunnel. Publish `18080:8080,51300-51399:51300-51399,51300-51399:51300-51399/udp`, and set:

```text
RUST_PROXY_PUBLIC_HOST=agent.example.com
RUST_PROXY_PUBLIC_PORT=18080
RUST_PROXY_SOCKS_HOST=socks.example.com
```

The dashboard only creates TCP SOCKS binds in that published range; UDP ASSOCIATE uses the same published UDP range. Create `agent` and `socks` as DNS-only records. Do not publish container port 8081 or place agent/SOCKS TCP/UDP traffic behind Cloudflare's standard HTTP proxy.

---

## Android Client Quick Start

1. Install the app via the Google Play Store (link at the top of the page) or grab the APK from the [Releases page](../../releases).
2. Open the app and manually enter your Server IP, Port, and Password **OR** tap **Scan QR** to instantly auto-configure using the "Mobile QR" code from the Web GUI.
3. Choose an Agent ID (e.g., `MyPhone`) so you can identify this device later.
4. Tap **Connect to VPS** to start tunneling. You can now close the app.

---

## PC Client Quick Start (Agent Mode)

You can run the RustProxy agent directly on any PC (Windows, Linux, macOS) to expose its connection.

1. Download the pre-compiled `rust_proxy` executable for your OS from the [Releases page](../../releases).
2. Run the executable in `agent` mode, pointing it to your public Control Server:
```bash
./rust_proxy agent -s "<YOUR_VPS_IP>:8080" -a "MyDesktopPC" -p "AgentPassword123"
```
- `-s`: The IP and Port of your Control Server (use the `--control-port`, not the api port).
- `-a`: Your custom Agent ID name to display in the Dashboard.
- `-p`: The secure server password.

### Enabling Remote IP Reset (Airplane Mode Toggle)

To allow the server to toggle airplane mode and force a new cellular IP:
1. Tap the **Set App as Assistant** button in the app.
2. Choose `RustProxy` as your default Digital Assistant.
3. You can now use the `Copy Link` button in the Web GUI's Agent list to securely trigger the IP rotation.

---

## Security Best Practices

- Use distinct strong `-p` and `--admin-password` values. The dashboard/API is private on `127.0.0.1`.
- Never share IP reset links publicly; each grants a short-rate-limited reset command for one agent.

---

## For Developers: Building From Source

If you want to compile the project yourself:

### Building the Rust Server
```bash
# Compile for Linux (from Windows or Linux)
cross build --release --target x86_64-unknown-linux-gnu

# Or compile natively
cargo build --release
```

## License
MIT License
