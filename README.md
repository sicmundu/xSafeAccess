# xSafeAccess - Secure Remote Access Setup

`xSafeAccess` is a Bash script designed to simplify and automate the setup of secure remote access to your Linux machine. It provides an interactive, user-friendly interface to install and configure Tailscale, ngrok, and an autossh reverse tunnel, ensuring you can always reach your machine.


![Снимок экрана 2025-06-01 в 09 56 45](https://github.com/user-attachments/assets/15a9adf8-cc66-4896-bccc-c6006bd9f60d)


## 🚀 Features

*   **Interactive Menu**: A user-friendly menu powered by `gum` for easy navigation and operation.
*   **Tailscale Integration**: Installs and helps authenticate Tailscale for a secure VPN connection.
*   **ngrok Integration**: Configures ngrok to expose your local SSH port via a public TCP tunnel with a fixed address.
*   **Autossh Reverse Tunnel**: Sets up a persistent reverse SSH tunnel to a VPS as a reliable fallback access method.
*   **Service Management**: Allows installation of all services at once or individual services.
*   **Status Checks**: View the status of each configured service.
*   **Reconfiguration**: Easily reconfigure services if your details change.
*   **Autonomous `gum` Installation**: Attempts to automatically install the `gum` dependency if it's not found.
*   **Comprehensive Logging**: All script actions and command outputs are logged to `/var/log/xsafe-access.log`.
*   **Colored Output & Spinners**: Enhanced visual feedback during operations.

## ⚙️ Dependencies

Before running the script, ensure you have `sudo` privileges. The script will attempt to install or guide you to install the following if they are missing:

*   **`gum`**: For the interactive TUI. The script will try to install this automatically.
*   **Core Utilities**: `curl`, `jq`, `openssh-client`, `autossh`, `gpg` (for adding Charmbracelet repo), `sed`. The script attempts to install these if missing (usually via `apt-get` during the `gum` or initial setup).

## ▶️ Getting Started

1.  **Clone the repository or download the script:**
    ```bash
    git clone https://github.com/sicmundu/xSafeAccess.git
    cd xSafeAccess
    ```
    Or download `xSafeAccess.sh` directly.

2.  **Make the script executable:**
    ```bash
    chmod +x xSafeAccess.sh
    ```

3.  **Run the script:**
    ```bash
    ./xSafeAccess.sh
    ```

## 🛠️ Usage

Upon running the script, you will be greeted with an interactive menu:

*   **Install All Services**: Sets up Tailscale, ngrok, and autossh with your provided details.
*   **Install/Configure [Service Name]**: Allows individual installation or reconfiguration of Tailscale, ngrok, or autossh.
    *   If a service is already configured, you'll be prompted if you wish to reconfigure it.
    *   Current configuration values will be shown as defaults during reconfiguration.
*   **[Service Name] (Status) - Reconfigure/Manage**: If a service is installed, this option allows you to view its status or re-trigger the configuration process.
*   **Check All Services Status**: Displays the current status of all managed services.
*   **View Logs**: Opens the `/var/log/xsafe-access.log` file using `gum pager` for easy viewing.
*   **Exit**: Exits the script.

Follow the on-screen prompts. The script will guide you through providing necessary information like VPS IP, ngrok authtoken, etc.

## 📝 Logging

All operations, user inputs (sensitive data like tokens are masked or not logged directly), and command outputs are logged to:
`/var/log/xsafe-access.log`

You can view these logs directly from the script menu or using standard Linux commands (`cat`, `less`, `tail`).

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/sicmundu/xSafeAccess/issues).

## 📄 License

This project is open source. Feel free to use, modify, and distribute it.
(Consider adding a specific license file like MIT, Apache 2.0, etc., if you wish.)

---

*This script is provided as-is. Always review scripts from the internet before running them on your system, especially those requiring sudo privileges.* 
