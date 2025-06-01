#!/bin/bash

set -e

# === Colors ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

LOG_FILE="/var/log/xsafe-access.log"

# Ensure log file exists and is writable
sudo touch $LOG_FILE
sudo chmod 666 $LOG_FILE # Allow current user to write, systemd services run as $LOCAL_USER or root

# === Gum Check & Auto-Installation ===
check_gum_installed() {
    if command -v gum &> /dev/null; then
        log_message "INFO" "gum is already installed."
        return 0
    fi

    echo -e "${YELLOW}xSafeAccess requires \`gum\` for its interactive menu, but it was not found.${NC}"
    read -rp "Attempt to install gum automatically? (yes/no): " autoinstall_gum_choice

    if [[ "$autoinstall_gum_choice" =~ ^[Yy](es)?$ ]]; then
        log_message "INFO" "User agreed to automatic gum installation attempt."
        echo -e "${BLUE}ℹ️ Attempting to detect your OS and package manager to install gum...${NC}"
        
        local installed_successfully=false

        # Check for common package managers
        if command -v apt-get &> /dev/null; then
            echo "Detected apt-get (Debian/Ubuntu). Attempting to install gum..."
            log_message "INFO" "Attempting gum install via apt-get."
            # Add Charmbracelet repo and install gum
            if sudo mkdir -p /etc/apt/keyrings && curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg && \
               echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list && \
               sudo apt-get update -y && sudo apt-get install -y gum; then
                log_message "SUCCESS" "gum installed successfully via apt-get."
                print_success "gum installed successfully!"
                installed_successfully=true
            else
                log_message "ERROR" "Failed to install gum via apt-get."
                print_error "Failed to install gum via apt-get. You may need to run the commands manually or check permissions."
            fi
        elif command -v brew &> /dev/null; then
            echo "Detected Homebrew (macOS/Linux). Attempting to install gum..."
            log_message "INFO" "Attempting gum install via Homebrew."
            if brew install gum; then
                log_message "SUCCESS" "gum installed successfully via Homebrew."
                print_success "gum installed successfully!"
                installed_successfully=true
            else
                log_message "ERROR" "Failed to install gum via Homebrew."
                print_error "Failed to install gum via Homebrew."
            fi
        elif command -v pacman &> /dev/null; then
            echo "Detected pacman (Arch Linux). Attempting to install gum..."
            log_message "INFO" "Attempting gum install via pacman."
            if sudo pacman -Syu --noconfirm gum; then # -Syu to ensure system is updated, --noconfirm for automation
                log_message "SUCCESS" "gum installed successfully via pacman."
                print_success "gum installed successfully!"
                installed_successfully=true
            else
                log_message "ERROR" "Failed to install gum via pacman."
                print_error "Failed to install gum via pacman."
            fi
        elif command -v dnf &> /dev/null; then
            echo "Detected dnf (Fedora/RHEL). Attempting to install gum..."
            log_message "INFO" "Attempting gum install via dnf."
            # For Fedora, gum is often in the main repos or available via copr
            # This is a common way to install it if directly available:
            if sudo dnf install -y gum; then
                log_message "SUCCESS" "gum installed successfully via dnf."
                print_success "gum installed successfully!"
                installed_successfully=true
            else
                log_message "WARNING" "Could not install gum directly with dnf. Trying Charmbracelet RPM setup..."
                # Attempt Charmbracelet RPM setup (similar to apt)
                # See https://github.com/charmbracelet/gum#rpm
                # Note: This might be more involved than a simple dnf install for some users
                # For now, let's keep it simpler and fall back to manual if direct dnf fails
                print_warning "Direct dnf install failed. Manual installation might be needed."
                # Fallback to manual instructions for now if direct dnf fails
                # To be more comprehensive: could add the COPR repo commands here.
            fi
        elif command -v yum &> /dev/null; then # For older RHEL/CentOS
             echo "Detected yum (Older RHEL/CentOS). Attempting to install gum..."
             log_message "INFO" "Attempting gum install via yum (may require EPEL or Charmbracelet RPM setup)."
             if sudo yum install -y gum; then
                log_message "SUCCESS" "gum installed successfully via yum."
                print_success "gum installed successfully!"
                installed_successfully=true
             else
                log_message "WARNING" "Could not install gum directly with yum. Manual installation or EPEL/Charmbracelet repo setup might be needed."
                print_warning "Direct yum install failed. Manual installation might be needed."
             fi   
        elif command -v nix-env &> /dev/null; then
            echo "Detected Nix. Attempting to install gum..."
            log_message "INFO" "Attempting gum install via nix-env."
            if nix-env -iA nixpkgs.gum; then
                log_message "SUCCESS" "gum installed successfully via nix-env."
                print_success "gum installed successfully!"
                installed_successfully=true
            else
                log_message "ERROR" "Failed to install gum via nix-env."
                print_error "Failed to install gum via nix-env."
            fi    
        else
            log_message "WARNING" "Could not detect a known package manager (apt, brew, pacman, dnf, yum, nix-env)."
            print_warning "Could not detect a common package manager."
        fi

        if $installed_successfully && command -v gum &> /dev/null; then
            log_message "INFO" "gum auto-installation successful and verified."
            return 0
        else
            log_message "ERROR" "Automatic installation of gum failed or was not attempted for your system."
            print_error "Automatic installation of gum failed or was not supported for your detected OS/package manager."
        fi
    else
        log_message "INFO" "User declined automatic gum installation."
    fi

    # Fallback to manual instructions if auto-install failed or was declined
    echo -e "\n${RED}Error: \`gum\` is still not installed or not in your PATH.${NC}"
    echo -e "${YELLOW}xSafeAccess requires \`gum\` for its interactive menu.${NC}"
    echo "Please install it manually from: https://github.com/charmbracelet/gum#installation"
    echo "Common installation methods (if auto-install failed, try these commands directly):"
    echo "  Debian/Ubuntu: sudo mkdir -p /etc/apt/keyrings && curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg && echo \"deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *\" | sudo tee /etc/apt/sources.list.d/charm.list && sudo apt update && sudo apt install gum"
    echo "  Homebrew (macOS/Linux): brew install gum"
    echo "  Arch Linux: sudo pacman -Syu gum"
    echo "  Fedora/RHEL (dnf): sudo dnf install gum (or follow RPM instructions on gum's GitHub)"
    echo "  Nix: nix-env -iA nixpkgs.gum"
    echo "  Windows (Scoop): scoop install gum"
    echo "Or download a binary from the releases page: https://github.com/charmbracelet/gum/releases"
    log_message "ERROR" "gum not found, script exiting after providing manual instructions."
    exit 1
}

# === Global Status Variables ===
TAILSCALE_STATUS="unknown"
NGROK_STATUS="unknown"
AUTOSSH_STATUS="unknown"
NGROK_CONFIGURED_REMOTE_ADDR=""
AUTOSSH_TUNNEL_INFO=""
TAILSCALE_IP_ADDR=""

# === Helper Functions ===
log_message() {
    local type=$1
    local message=$2
    local plain_message
    # Remove emojis for log file if needed, or simplify
    plain_message=$(echo "$message" | sed 's/✅ //g; s/❌ //g; s/⚠️ //g; s/ℹ️ //g; s/🚀 //g; s/🔄 //g; s/🛠️ //g; s/🔑 //g; s/⚙️ //g; s/📤 //g; s/🎉 //g')

    echo -e "$message" # Output to console with color/emoji
    echo "$(date +'%Y-%m-%d %H:%M:%S') [$type] $plain_message" >> "$LOG_FILE"
}

print_success() {
    log_message "SUCCESS" "${GREEN}✅ $1${NC}"
}

print_error() {
    log_message "ERROR" "${RED}❌ $1${NC}"
}

print_warning() {
    log_message "WARNING" "${YELLOW}⚠️ $1${NC}"
}

print_info() {
    log_message "INFO" "${BLUE}ℹ️ $1${NC}"
}

# Spinner/loader function
spinner() {
    local pid=$1
    local message=${2:-Processing...}
    local delay=0.1
    local spinstr='|/-\'
    echo -n "$message  " | tee -a "$LOG_FILE" # Log spinner start message
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf "[%c]  " "$spinstr"
        local spinstr=$temp${spinstr%???}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
    echo "Done!" | tee -a "$LOG_FILE" # Log spinner end message
}

# === Service Installation Functions ===
install_tailscale() {
    update_tailscale_status # Get current status
    if [[ "$TAILSCALE_STATUS" == "not_installed" ]]; then
        print_info "Starting Tailscale installation..."
        log_message "INFO" "🛠️ [xSafeAccess] Installing tailscale..."
        (curl -fsSL https://tailscale.com/install.sh | sudo sh) >> "$LOG_FILE" 2>&1 &
        spinner $! "Installing Tailscale..."
        print_success "Tailscale installed."
        (sudo systemctl enable --now tailscaled) >> "$LOG_FILE" 2>&1
        log_message "INFO" "🔑 [xSafeAccess] Authenticate Tailscale (browser will open or URL will be shown):"
        sudo tailscale up >> "$LOG_FILE" 2>&1
        print_success "Tailscale authenticated and up."
    else
        print_info "Tailscale is already installed ($TAILSCALE_STATUS)."
        if gum confirm "Do you want to re-authenticate or change Tailscale user?" --affirmative="Yes, Reconfigure" --negative="No, Skip"; then
            if gum confirm "Logout current Tailscale user first?" --affirmative="Yes, Logout" --negative="No, Just Re-auth"; then
                print_info "Logging out from Tailscale..."
                sudo tailscale logout >> "$LOG_FILE" 2>&1
                print_success "Logged out."
            fi
            log_message "INFO" "🔑 [xSafeAccess] Re-authenticating Tailscale (browser will open or URL will be shown):"
            sudo tailscale up >> "$LOG_FILE" 2>&1
            print_success "Tailscale re-authentication process started."
        else
            print_info "Skipping Tailscale re-configuration."
        fi
    fi
    update_all_statuses # Update status after action
}

install_ngrok() {
    update_ngrok_status # Get current status
    local perform_setup=true

    if [[ "$NGROK_STATUS" != "not_installed" && "$NGROK_STATUS" != "installed_config_missing" && "$NGROK_STATUS" != "installed_config_incomplete" ]]; then
        print_info "ngrok seems to be already configured ($NGROK_STATUS)."
        if ! gum confirm "Do you want to re-configure ngrok (token, remote_addr)?" --affirmative="Yes, Reconfigure" --negative="No, Skip"; then
            perform_setup=false
            print_info "Skipping ngrok re-configuration."
        fi
    fi

    if $perform_setup; then
        print_info "Starting ngrok configuration..."
        local old_token=""
        local old_remote_addr=""
        local ngrok_config_file="/home/$LOCAL_USER/.config/ngrok/ngrok.yml"

        if [ -f "$ngrok_config_file" ]; then
            old_token=$(grep 'authtoken:' "$ngrok_config_file" | awk '{print $2}')
            old_remote_addr=$(grep 'remote_addr:' "$ngrok_config_file" | awk '{print $2}')
        fi

        NGROK_TOKEN=$(gum input --value "$old_token" --placeholder "Ngrok Authtoken" --prompt="Enter ngrok authtoken: ")
        log_message "INPUT" "NGROK_TOKEN: ****"
        
        NGROK_REMOTE=$(gum input --value "$old_remote_addr" --placeholder "e.g. 1.tcp.ngrok.io:12345" --prompt="Enter desired fixed remote_addr: ")
        log_message "INPUT" "NGROK_REMOTE: $NGROK_REMOTE"

        if [ -z "$NGROK_TOKEN" ] || [ -z "$NGROK_REMOTE" ]; then
            print_error "ngrok authtoken and remote_addr are required. Configuration aborted."
            update_all_statuses
            return 1
        fi 

        mkdir -p "/home/$LOCAL_USER/.config/ngrok"
        cat <<EOF > "$ngrok_config_file"
authtoken: $NGROK_TOKEN
version: 2
tunnels:
  ssh:
    proto: tcp
    addr: 22
    remote_addr: $NGROK_REMOTE
EOF
        chown -R "$LOCAL_USER:$LOCAL_USER" "/home/$LOCAL_USER/.config/ngrok"
        print_success "ngrok configuration file updated/created."

        # Ensure ngrok command is available
        if ! command -v ngrok >/dev/null 2>&1; then
            print_error "ngrok command not found. Please install ngrok first (this script does not manage ngrok binary installation)."
            # Or add ngrok binary installation here if desired
            update_all_statuses
            return 1
        fi

        cat <<EOF | sudo tee /etc/systemd/system/ngrok.service > /dev/null
[Unit]
Description=ngrok tunnel $NGROK_REMOTE
After=network.target

[Service]
User=$LOCAL_USER
ExecStart=/usr/bin/ngrok start --all --config "$ngrok_config_file"
Restart=always
Environment=TERM=xterm-256color
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOF

        (sudo systemctl daemon-reload) >> "$LOG_FILE" 2>&1
        (sudo systemctl enable --now ngrok) >> "$LOG_FILE" 2>&1
        (sudo systemctl restart ngrok) >> "$LOG_FILE" 2>&1 # Restart to apply new config
        print_success "ngrok service reconfigured and restarted."
        NGROK_CONFIGURED_REMOTE_ADDR=$NGROK_REMOTE # Update global var
    fi
    update_all_statuses # Update status after action
}

install_autossh() {
    update_autossh_status # Get current status
    local perform_setup=true
    local autossh_service_file="/etc/systemd/system/autossh-vps.service"

    if [[ "$AUTOSSH_STATUS" != "not_installed" && "$AUTOSSH_STATUS" != "installed_config_missing" && "$AUTOSSH_STATUS" != "installed_config_incomplete" && "$AUTOSSH_STATUS" != "installed_running_config_unclear" && "$AUTOSSH_STATUS" != "installed_not_running_config_unclear" ]]; then
        print_info "autossh seems to be already configured ($AUTOSSH_STATUS)."
        if ! gum confirm "Do you want to re-configure autossh (VPS details, ports, key)?" --affirmative="Yes, Reconfigure" --negative="No, Skip"; then
            perform_setup=false
            print_info "Skipping autossh re-configuration."
        fi
    fi

    if $perform_setup; then
        print_info "Starting autossh configuration..."
        
        local old_vps_ip=""
        local old_vps_port="22"
        local old_remote_port="6001"
        local old_ssh_key_path="/home/$LOCAL_USER/.ssh/id_vps_autossh"

        if [ -f "$autossh_service_file" ]; then
            local exec_start_line=$(grep ExecStart "$autossh_service_file")
            old_vps_ip=$(echo "$exec_start_line" | sed -n 's/.*@\([^ ]*\) -p.*/\1/p')
            old_vps_port=$(echo "$exec_start_line" | sed -n 's/.*-p \([0-9]*\).*/\1/p')
            old_remote_port=$(echo "$exec_start_line" | sed -n 's/.*0\.0\.0\.0:\([^:]*\):localhost:22.*/\1/p')
            old_ssh_key_path=$(echo "$exec_start_line" | sed -n 's/.*-i \([^ ]*\) .*/\1/p')
        fi

        VPS_IP_AUTOSSH=$(gum input --value "$old_vps_ip" --placeholder "VPS IP Address" --prompt="Enter VPS IP (for autossh reverse tunnel): ")
        log_message "INPUT" "VPS_IP_AUTOSSH: $VPS_IP_AUTOSSH"
        
        VPS_PORT_AUTOSSH=$(gum input --value "$old_vps_port" --placeholder "22" --prompt="Enter VPS SSH port: ")
        log_message "INPUT" "VPS_PORT_AUTOSSH: $VPS_PORT_AUTOSSH"
        
        REMOTE_PORT_AUTOSSH=$(gum input --value "$old_remote_port" --placeholder "6001" --prompt="Enter port to expose on VPS: ")
        log_message "INPUT" "REMOTE_PORT_AUTOSSH: $REMOTE_PORT_AUTOSSH"

        SSH_KEY_PATH=$(gum input --value "$old_ssh_key_path" --placeholder "/home/$LOCAL_USER/.ssh/id_vps_autossh" --prompt="Path to SSH private key for autossh: ")
        log_message "INPUT" "SSH_KEY_PATH: $SSH_KEY_PATH"

        if [ -z "$VPS_IP_AUTOSSH" ] || [ -z "$VPS_PORT_AUTOSSH" ] || [ -z "$REMOTE_PORT_AUTOSSH" ] || [ -z "$SSH_KEY_PATH" ]; then
            print_error "VPS IP, VPS Port, Remote Port, and SSH Key Path are required. Configuration aborted."
            update_all_statuses
            return 1
        fi

        if [ ! -f "$SSH_KEY_PATH" ]; then
            print_warning "SSH key $SSH_KEY_PATH does not exist."
            if gum confirm "Create SSH key $SSH_KEY_PATH now?" --affirmative="Yes, Create" --negative="No, Abort"; then
                 log_message "INFO" "🔑 [xSafeAccess] Creating SSH key $SSH_KEY_PATH..."
                (sudo -u "$LOCAL_USER" ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "") >> "$LOG_FILE" 2>&1 || true
                print_success "SSH key $SSH_KEY_PATH created/ensured."
            else
                print_error "SSH key not found. Configuration aborted."
                update_all_statuses
                return 1
            fi
        fi
        
        print_info "Important: Ensure the public key for $SSH_KEY_PATH (i.e., ${SSH_KEY_PATH}.pub) is in authorized_keys on $VPS_IP_AUTOSSH for user root."
        if gum confirm "Attempt ssh-copy-id for this key to $VPS_IP_AUTOSSH?" --affirmative="Yes, Copy ID" --negative="No, Skip"; then
            log_message "INFO" "📤 [xSafeAccess] Copying public key ${SSH_KEY_PATH}.pub to $VPS_IP_AUTOSSH..."
            (sudo -u "$LOCAL_USER" ssh-copy-id -p "$VPS_PORT_AUTOSSH" -i "$SSH_KEY_PATH" "root@$VPS_IP_AUTOSSH") >> "$LOG_FILE" 2>&1
            print_success "SSH key copied to VPS (or attempt made)."
        fi

        cat <<EOF | sudo tee "$autossh_service_file" > /dev/null
[Unit]
Description=AutoSSH reverse tunnel to $VPS_IP_AUTOSSH:$REMOTE_PORT_AUTOSSH
After=network.target

[Service]
User=$LOCAL_USER
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/bin/autossh -M 0 -N \
  -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
  -o "StrictHostKeyChecking=accept-new" -o "ExitOnForwardFailure=yes" \
  -i "$SSH_KEY_PATH" \
  -R 0.0.0.0:$REMOTE_PORT_AUTOSSH:localhost:22 root@$VPS_IP_AUTOSSH -p $VPS_PORT_AUTOSSH
Restart=always
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOF

        (sudo systemctl daemon-reload) >> "$LOG_FILE" 2>&1
        (sudo systemctl enable --now autossh-vps) >> "$LOG_FILE" 2>&1 # ensure it is enabled
        (sudo systemctl restart autossh-vps) >> "$LOG_FILE" 2>&1 # Restart to apply
        print_success "autossh service reconfigured and restarted."
        VPS_IP_FOR_TUNNEL=$VPS_IP_AUTOSSH
        REMOTE_PORT_FOR_TUNNEL=$REMOTE_PORT_AUTOSSH
        if [ -n "$VPS_IP_FOR_TUNNEL" ] && [ -n "$REMOTE_PORT_FOR_TUNNEL" ] && [ -n "$LOCAL_USER" ]; then
            AUTOSSH_TUNNEL_INFO="ssh -p $REMOTE_PORT_FOR_TUNNEL $LOCAL_USER@$VPS_IP_FOR_TUNNEL"
        fi
    fi
    update_all_statuses # Update status after action
}

install_all_services() {
    print_info "Starting installation of all services..."
    # Common packages
    log_message "INFO" "🔄 [xSafeAccess] Installing common packages..."
    (sudo apt-get update -y) >> "$LOG_FILE" 2>&1 &
    spinner $! "Updating package lists..."
    log_message "INFO" "Packages updated."
    (sudo apt-get install -y autossh jq curl openssh-client) >> "$LOG_FILE" 2>&1 &
    spinner $! "Installing core packages (autossh, jq, curl, openssh-client)..."
    print_success "Core packages installed."

    # User info needed by multiple services
    if [ -z "$LOCAL_USER" ]; then
        print_info "Local username is required for many operations."
        LOCAL_USER=$(gum input --placeholder "Enter local username (e.g., markapola)" --prompt="Please enter your local username: ")
        if [ -z "$LOCAL_USER" ]; then
            print_error "Local username is required to proceed. Exiting."
            log_message "ERROR" "LOCAL_USER not provided at initial prompt. Exiting."
            exit 1
        fi
        log_message "INPUT" "LOCAL_USER initially set to: $LOCAL_USER"
    fi

    install_tailscale
    install_ngrok
    install_autossh
    print_success "All services installed and configured!"
    update_all_statuses # Update status after action
}

# === Service Status Update Functions (Replaces old check_* functions) ===
update_tailscale_status() {
    TAILSCALE_IP_ADDR=""
    if command -v tailscale >/dev/null 2>&1; then
        if systemctl is-active --quiet tailscaled; then
            TAILSCALE_STATUS="installed_running"
            TAILSCALE_IP_ADDR=$(tailscale ip -4 2>> "$LOG_FILE" || echo "Not connected")
        else
            TAILSCALE_STATUS="installed_not_running"
        fi
    else
        TAILSCALE_STATUS="not_installed"
    fi
}

update_ngrok_status() {
    NGROK_CONFIGURED_REMOTE_ADDR=""
    local ngrok_config_file="/home/$LOCAL_USER/.config/ngrok/ngrok.yml"

    if ! command -v ngrok >/dev/null 2>&1; then
        NGROK_STATUS="not_installed"
        return
    fi

    if [ ! -f "$ngrok_config_file" ]; then
        NGROK_STATUS="installed_config_missing"
        return
    fi

    NGROK_CONFIGURED_REMOTE_ADDR=$(grep 'remote_addr:' "$ngrok_config_file" | awk '{print $2}' || echo "")
    if [ -z "$NGROK_CONFIGURED_REMOTE_ADDR" ]; then
         NGROK_STATUS="installed_config_incomplete"
         return
    fi

    if systemctl is-active --quiet ngrok; then
        NGROK_STATUS="installed_running"
    else
        NGROK_STATUS="installed_not_running"
    fi
}

update_autossh_status() {
    AUTOSSH_TUNNEL_INFO=""
    local autossh_service_file="/etc/systemd/system/autossh-vps.service"

    if ! command -v autossh >/dev/null 2>&1; then
        AUTOSSH_STATUS="not_installed"
        return
    fi

    if [ ! -f "$autossh_service_file" ]; then
        AUTOSSH_STATUS="installed_config_missing" # Service file itself is the config
        return
    fi

    # Try to derive tunnel info from service file
    # Format: ssh -p REMOTE_PORT LOCAL_USER@VPS_IP
    local exec_start_line=$(grep ExecStart "$autossh_service_file")
    local remote_port=$(echo "$exec_start_line" | sed -n 's/.*-R [^:]*:\([^:]*\):localhost:22.*/\1/p') #This was wrong, should be the port on VPS
    remote_port=$(echo "$exec_start_line" | sed -n 's/.*0\.0\.0\.0:\([^:]*\):localhost:22.*/\1/p')

    local vps_ip=$(echo "$exec_start_line" | sed -n 's/.*@\([^ ]*\) -p.*/\1/p')
    # User might be different, but $LOCAL_USER should be correct for the created service
    if [ -n "$remote_port" ] && [ -n "$vps_ip" ] && [ -n "$LOCAL_USER" ]; then
         AUTOSSH_TUNNEL_INFO="ssh -p $remote_port $LOCAL_USER@$vps_ip"
    else
        # If parsing failed, check if we have it from install_autossh run
        if [ -n "$VPS_IP_FOR_TUNNEL" ] && [ -n "$REMOTE_PORT_FOR_TUNNEL" ] && [ -n "$LOCAL_USER" ]; then
             AUTOSSH_TUNNEL_INFO="ssh -p $REMOTE_PORT_FOR_TUNNEL $LOCAL_USER@$VPS_IP_FOR_TUNNEL"
        fi
    fi
    
    if [ -z "$AUTOSSH_TUNNEL_INFO" ]; then
        AUTOSSH_STATUS="installed_config_incomplete"
        #return # Do not return yet, check if running
    fi

    if systemctl is-active --quiet autossh-vps; then
        # If it is running and we couldn't get tunnel info, it is still running
        # If we got tunnel info, it is running with that config
        if [ -z "$AUTOSSH_TUNNEL_INFO" ] && [[ "$AUTOSSH_STATUS" == "installed_config_incomplete" ]]; then 
             AUTOSSH_STATUS="installed_running_config_unclear"
        else 
             AUTOSSH_STATUS="installed_running"
        fi
    else
        if [ -z "$AUTOSSH_TUNNEL_INFO" ] && [[ "$AUTOSSH_STATUS" == "installed_config_incomplete" ]]; then
            AUTOSSH_STATUS="installed_not_running_config_unclear"
        else 
            AUTOSSH_STATUS="installed_not_running"
        fi
    fi
}

update_all_statuses() {
    log_message "INFO" "Updating all service statuses..."
    # Requires LOCAL_USER to be set for ngrok and autossh config paths
    if [ -z "$LOCAL_USER" ]; then
        # This should ideally be set before calling this, e.g., in main()
        log_message "WARNING" "LOCAL_USER not set, some statuses might be inaccurate."
        # Attempt to prompt for it if critical and missing, though main() should catch this.
        if ! gum confirm "LOCAL_USER is not set. It is required for some operations. Set it now?" --affirmative="Set User" --negative="Skip"; then 
            log_message "ERROR" "LOCAL_USER not set by user. Some operations may fail."
        else
            LOCAL_USER=$(gum input --placeholder "Enter local username (e.g., markapola)" --prompt="Local Username: ")
            if [ -z "$LOCAL_USER" ]; then
                log_message "ERROR" "LOCAL_USER still not set. Some operations may fail."
            else 
                log_message "INPUT" "LOCAL_USER set to: $LOCAL_USER"
            fi
        fi
    fi
    update_tailscale_status
    update_ngrok_status
    update_autossh_status
    log_message "DEBUG" "Statuses: T:$TAILSCALE_STATUS, N:$NGROK_STATUS, A:$AUTOSSH_STATUS"
}

# === Functions to get status strings for menu ===
get_tailscale_menu_status_string() {
    case "$TAILSCALE_STATUS" in
        not_installed) echo "(Not Installed)";;
        installed_running) echo "(Running, IP: $TAILSCALE_IP_ADDR)";;
        installed_not_running) echo "(Installed, Not Running)";;
        *) echo "(Status Unknown)";;
    esac
}

get_ngrok_menu_status_string() {
    case "$NGROK_STATUS" in
        not_installed) echo "(Not Installed)";;
        installed_config_missing) echo "(Installed, Config Missing!)";;
        installed_config_incomplete) echo "(Installed, Config Incomplete!)";;
        installed_running) echo "(Running, Addr: $NGROK_CONFIGURED_REMOTE_ADDR)";;
        installed_not_running) echo "(Installed, Not Running)";;
        *) echo "(Status Unknown)";;
    esac
}

get_autossh_menu_status_string() {
    case "$AUTOSSH_STATUS" in
        not_installed) echo "(Not Installed)";;
        installed_config_missing) echo "(Installed, Config Missing!)";;
        installed_config_incomplete) echo "(Installed, Config Incomplete!)";;
        installed_running_config_unclear) echo "(Running, Config Unclear)";;
        installed_running) echo "(Running: $AUTOSSH_TUNNEL_INFO)";;
        installed_not_running_config_unclear) echo "(Installed, Not Running, Config Unclear)";;
        installed_not_running) echo "(Installed, Not Running)";;
        *) echo "(Status Unknown)";;
    esac
}

# === Display current statuses (for check options) ===
display_tailscale_status_details() {
    print_info "Tailscale Status Details:"
    log_message "INFO" "Raw Status: $TAILSCALE_STATUS"
    case "$TAILSCALE_STATUS" in
        not_installed) print_warning "Tailscale is not installed.";;
        installed_running) print_success "Tailscale service is running."; print_info "Tailscale IP: $TAILSCALE_IP_ADDR";;
        installed_not_running) print_error "Tailscale service is installed but NOT running.";;
        *) print_error "Could not determine Tailscale status clearly.";;
    esac
}

display_ngrok_status_details() {
    print_info "ngrok Status Details:"
    log_message "INFO" "Raw Status: $NGROK_STATUS"
    case "$NGROK_STATUS" in
        not_installed) print_warning "ngrok is not installed.";;
        installed_config_missing) print_error "ngrok is installed, but config file (/home/$LOCAL_USER/.config/ngrok/ngrok.yml) is missing!";;
        installed_config_incomplete) print_error "ngrok is installed, but remote_addr is not set in config file!";;
        installed_running) print_success "ngrok service is running."; print_info "Configured ngrok address: $NGROK_CONFIGURED_REMOTE_ADDR";;
        installed_not_running) print_error "ngrok service is installed but NOT running (config found: $NGROK_CONFIGURED_REMOTE_ADDR).";;
        *) print_error "Could not determine ngrok status clearly.";;
    esac
}

display_autossh_status_details() {
    print_info "autossh (VPS Tunnel) Status Details:"
    log_message "INFO" "Raw Status: $AUTOSSH_STATUS"
    case "$AUTOSSH_STATUS" in
        not_installed) print_warning "autossh is not installed.";;
        installed_config_missing) print_error "autossh is installed, but service file (/etc/systemd/system/autossh-vps.service) is missing!";;
        installed_config_incomplete) print_error "autossh is installed, but tunnel configuration is incomplete or could not be parsed from service file.";;
        installed_running_config_unclear) print_success "autossh service is running, but tunnel details could not be fully parsed from service file.";;
        installed_running) print_success "autossh service (VPS tunnel) is running."; print_info "Tunnel: $AUTOSSH_TUNNEL_INFO";;
        installed_not_running_config_unclear) print_error "autossh service is installed but NOT running; tunnel details could not be fully parsed.";;
        installed_not_running) print_error "autossh service is installed but NOT running (expected tunnel: $AUTOSSH_TUNNEL_INFO).";;
        *) print_error "Could not determine autossh status clearly.";;
    esac
}

# === Menu Functions ===
show_menu_and_get_choice() {
    update_all_statuses # Ensure statuses are fresh before displaying menu

    local header="xSafeAccess Menu - Select an option:"
    local options=()
    
    # Option 1: Install All
    options+=("Install All Services (Tailscale, ngrok, autossh)")
    
    # Tailscale
    local ts_status_str=$(get_tailscale_menu_status_string)
    if [[ "$TAILSCALE_STATUS" == "not_installed" ]]; then
        options+=("Install Tailscale $ts_status_str")
    else
        options+=("Tailscale $ts_status_str - Reconfigure/Manage")
    fi

    # ngrok
    local ng_status_str=$(get_ngrok_menu_status_string)
    if [[ "$NGROK_STATUS" == "not_installed" || "$NGROK_STATUS" == "installed_config_missing" || "$NGROK_STATUS" == "installed_config_incomplete" ]]; then
        options+=("Install/Configure ngrok $ng_status_str")
    else
        options+=("ngrok $ng_status_str - Reconfigure/Manage")
    fi

    # autossh
    local as_status_str=$(get_autossh_menu_status_string)
    if [[ "$AUTOSSH_STATUS" == "not_installed" || "$AUTOSSH_STATUS" == "installed_config_missing" || "$AUTOSSH_STATUS" == "installed_config_incomplete" || "$AUTOSSH_STATUS" == "installed_running_config_unclear" || "$AUTOSSH_STATUS" == "installed_not_running_config_unclear" ]]; then
        options+=("Install/Configure autossh $as_status_str")
    else
        options+=("autossh $as_status_str - Reconfigure/Manage")
    fi

    options+=("Check All Services Status")
    options+=("View Logs (/var/log/xsafe-access.log)")
    options+=("Exit")

    # Use gum choose
    # The --height option can be adjusted if there are more/less items
    # Use printf to pass options one per line to gum choose
    local choice
    choice=$(printf "%s\n" "${options[@]}" | gum choose --header "$header" --height 10)
    
    # Check if user pressed Esc or Ctrl+C (gum choose returns empty string)
    if [ -z "$choice" ]; then
        log_message "INFO" "User cancelled menu selection (Esc/Ctrl+C)."
        # Decide if we should exit or just re-prompt. For now, re-prompt by returning empty.
        # To exit, use: print_info "Exiting due to cancelled selection."; exit 0
        echo "" # Return empty to re-prompt in the loop or handle as cancel
        return
    fi

    echo "$choice"
}

main() {
    # Initial package check and install for essential tools like jq, curl, openssh-client (if not installing all)
    # For now, assuming 'install all' will handle this, or they are pre-reqs.
    # Consider adding a check here if script is run without 'install all' first.

    # Initial prompts that are needed for multiple individual installs or status checks
    # Prompt for LOCAL_USER if not set, as it's used by ngrok, autossh, and status checks for config paths
    if [ -z "$LOCAL_USER" ]; then
        print_info "Local username is required for many operations."
        LOCAL_USER=$(gum input --placeholder "Enter local username (e.g., markapola)" --prompt="Please enter your local username: ")
        if [ -z "$LOCAL_USER" ]; then
            print_error "Local username is required to proceed. Exiting."
            log_message "ERROR" "LOCAL_USER not provided at initial prompt. Exiting."
            exit 1
        fi
        log_message "INPUT" "LOCAL_USER initially set to: $LOCAL_USER"
    fi

    update_all_statuses # Initial status update

    while true; do
        # Clear screen for better menu visibility with gum
        # clear # Optional: uncomment if you prefer a full clear screen
        
        local choice
        choice=$(show_menu_and_get_choice)

        # If choice is empty (Esc/Ctrl+C from gum choose), redisplay menu or exit
        if [ -z "$choice" ]; then
            # To exit on cancel: print_info "Exiting due to cancelled selection."; exit 0
            # To re-prompt, just continue the loop
            log_message "INFO" "Menu selection cancelled, re-displaying."
            echo # Add a newline for readability
            sleep 1 # Brief pause before re-displaying
            continue
        fi
        
        # Log the user's choice
        log_message "MENU_CHOICE" "User selected: $choice"

        case "$choice" in
            "Install All Services (Tailscale, ngrok, autossh)") install_all_services ;;
            # Need to use pattern matching for dynamic parts of menu items
            "Install Tailscale "*) install_tailscale ;;
            "Tailscale "*) install_tailscale ;;
            
            "Install/Configure ngrok "*) install_ngrok ;;
            "ngrok "*) install_ngrok ;;

            "Install/Configure autossh "*) install_autossh ;;
            "autossh "*) install_autossh ;;
            
            "Check All Services Status") 
                display_tailscale_status_details
                display_ngrok_status_details
                display_autossh_status_details
                print_info "Select individual service options to re-configure or manage."
                gum spin --title "Pausing..." -- sleep 3 # Show status then pause
                ;;
            "View Logs (/var/log/xsafe-access.log)")
                print_info "Displaying logs (press q to quit):"
                gum pager < "$LOG_FILE"
                ;;
            "Exit") 
                print_info "Exiting xSafeAccess. Goodbye!"
                echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] User exited." >> "$LOG_FILE"
                exit 0 
                ;;
            *) 
                # This case should ideally not be reached if gum choose is used correctly
                # as it forces selection from the list.
                print_warning "Invalid option: '$choice'. This should not happen with gum menu."
                log_message "WARNING" "Invalid menu choice detected: $choice"
                ;;
        esac
        # echo # Add a newline for readability before next menu display - less needed with gum
        # Consider a small pause or a "Press Enter to continue" if not clearing screen
        # gum confirm "Continue to menu?" || { print_info "Exiting."; exit 0; }
    done
}

### === xSafeAccess Installer === ###
# Old direct execution logic is now moved into functions and called by the menu.
# The script now starts by calling main().

check_gum_installed # Run check at the very beginning

print_info "🚀 [xSafeAccess] Script Initializing..."

# Perform essential package installations if they are missing (jq, curl, openssh-client, autossh)
# These are needed for the script to function correctly, even for menu display or individual installs.
REQUIRED_PACKAGES=("jq" "curl" "openssh-client" "autossh" "sed") # Added sed for log_message
MISSING_PACKAGES=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        MISSING_PACKAGES+=("$pkg")
    fi
done

if [ ${#MISSING_PACKAGES[@]} -ne 0 ]; then
    print_warning "The following required packages are missing: ${MISSING_PACKAGES[*]}"
    print_info "Attempting to install them..."
    (sudo apt-get update -y) >> "$LOG_FILE" 2>&1 &
    spinner $! "Updating package lists for prerequisites..."
    (sudo apt-get install -y "${MISSING_PACKAGES[@]}") >> "$LOG_FILE" 2>&1 &
    spinner $! "Installing missing prerequisite packages..."
    print_success "Required packages installed."
else
    print_info "All required core packages are already installed."
fi

# Call the main function to display the menu
main