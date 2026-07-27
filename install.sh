#!/usr/bin/env bash
# Script d'installation MSG
# Usage : ./install.sh

set -e

GREEN="\033[92m"
CYAN="\033[96m"
YELLOW="\033[93m"
RED="\033[91m"
R="\033[0m"
BOLD="\033[1m"

say()  { echo -e "${CYAN}▸${R} $1"; }
ok()   { echo -e "${GREEN}✓${R} $1"; }
warn() { echo -e "${YELLOW}⚠${R} $1"; }
err()  { echo -e "${RED}✗${R} $1"; }

echo -e "\n${BOLD}${CYAN}── Installation MSG ──${R}\n"

# ── Vérifier Python 3 ──────────────────────────────────────────────────────
say "Vérification de Python 3..."
if ! command -v python3 &>/dev/null; then
    err "Python 3 non trouvé."
    say "Installation de Python 3..."
    if command -v apt &>/dev/null; then
        sudo apt update -qq && sudo apt install -y python3 python3-pip
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm python python-pip
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3 python3-pip
    elif command -v brew &>/dev/null; then
        brew install python3
    else
        err "Impossible d'installer Python automatiquement. Installe-le manuellement."
        exit 1
    fi
fi
ok "Python $(python3 --version | awk '{print $2}') trouvé."

# ── pip ─────────────────────────────────────────────────────────────────────
say "Vérification de pip..."
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null 2>&1; then
    say "Installation de pip..."
    if command -v apt &>/dev/null; then
        sudo apt install -y python3-pip
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm python-pip
    fi
fi
ok "pip disponible."

# ── Dossier d'installation ──────────────────────────────────────────────────
INSTALL_DIR="$HOME/.local/lib/msg"
say "Installation dans $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$(dirname "$(realpath "$0")")"/* "$INSTALL_DIR/"

# ── Dépendances Python ──────────────────────────────────────────────────────
say "Installation des dépendances Python..."
python3 -m pip install --quiet --user -r "$INSTALL_DIR/requirements.txt"
ok "Dépendances installées."

# ── Créer la commande 'msg' dans ~/bin ──────────────────────────────────────
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

cat > "$BIN_DIR/msg" << EOF
#!/usr/bin/env bash
python3 "$INSTALL_DIR/client/msg.py" "\$@"
EOF
chmod +x "$BIN_DIR/msg"
ok "Commande 'msg' créée dans $BIN_DIR."

# ── Créer la commande 'msg-server' ──────────────────────────────────────────
cat > "$BIN_DIR/msg-server" << EOF
#!/usr/bin/env bash
python3 "$INSTALL_DIR/server/server.py" "\$@"
EOF
chmod +x "$BIN_DIR/msg-server"
ok "Commande 'msg-server' créée."

# ── Vérifier que ~/bin est dans le PATH ──────────────────────────────────────
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR n'est pas dans ton PATH."
    SHELL_RC=""
    if [[ -f "$HOME/.zshrc" ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ -f "$HOME/.bashrc" ]]; then
        SHELL_RC="$HOME/.bashrc"
    fi
    if [[ -n "$SHELL_RC" ]]; then
        echo "" >> "$SHELL_RC"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
        ok "PATH mis à jour dans $SHELL_RC"
        warn "Fais 'source $SHELL_RC' ou ouvre un nouveau terminal."
    fi
fi

# ── Tailscale ────────────────────────────────────────────────────────────────
echo ""
say "Vérification de Tailscale..."
if ! command -v tailscale &>/dev/null; then
    warn "Tailscale n'est pas installé."
    echo -e "  Installe-le avec :"
    echo -e "  ${CYAN}curl -fsSL https://tailscale.com/install.sh | sh${R}"
    echo -e "  Puis : ${CYAN}sudo tailscale up${R}"
    echo ""
else
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
    if [[ -n "$TAILSCALE_IP" ]]; then
        ok "Tailscale actif. Ton IP Tailscale : ${CYAN}$TAILSCALE_IP${R}"
    else
        warn "Tailscale installé mais pas connecté. Lance : ${CYAN}sudo tailscale up${R}"
    fi
fi

# ── Résumé ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}── Installation terminée ──${R}"
echo ""
echo -e "  ${BOLD}Si tu es l'admin (hébergeur du serveur) :${R}"
echo -e "    Lance le serveur  : ${CYAN}msg-server${R}"
echo -e "    Configure le client : ${CYAN}msg setup${R}  (utilise 127.0.0.1 comme IP)"
echo ""
echo -e "  ${BOLD}Si tu es un utilisateur :${R}"
echo -e "    ${CYAN}msg setup${R}  (utilise l'IP Tailscale de l'admin)"
echo ""
echo -e "  ${BOLD}Commandes principales :${R}"
echo -e "    ${CYAN}msg${R}                     — mode interactif"
echo -e "    ${CYAN}msg list${R}               — voir tes messages"
echo -e "    ${CYAN}msg @pseudo \"texte\"${R}    — envoyer un message"
echo -e "    ${CYAN}msg @pseudo fichier.pdf${R} — envoyer un fichier"
echo -e "    ${CYAN}msg contacts${R}           — voir les contacts"
echo -e "    ${CYAN}msg help${R}               — aide complète"
echo ""
