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
Upload the executable to your public VPS (like Ubuntu or Debian). Run it from the terminal and provide a secure password:
```bash
./rust_proxy server -p "MySecurePassword123" --control-port 8080 --api-port 8081
```

- `--api-port 8081`: This is where your Web Dashboard is hosted.
- `--control-port 8080`: This is the port your Android/PC agents connect to.

### 3. Open the Dashboard
Go to your VPS IP in your browser:
```
http://<YOUR_VPS_IP>:8081/
```
Enter the password you started the server with to gain access.

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
./rust_proxy agent -s "<YOUR_VPS_IP>:8080" -a "MyDesktopPC" -p "MySecurePassword123"
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

- Ensure your server is launched with a strong `-p` password, as the Web Dashboard and API endpoints are public and require it.
- Never share the IP reset links publicly; they contain your password embedded in them.

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
