#!/usr/bin/env python3
"""
Client MSG — interface terminal discrète
Usage : msg [commande] [args]
"""
import os
import sys
import json
import getpass
import configparser
import mimetypes
import asyncio
import time
import subprocess
import aiohttp
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.crypto import (
    generate_keypair, serialize_public_key, serialize_private_key,
    deserialize_private_key, deserialize_public_key,
    encrypt_message, decrypt_message,
    encrypt_file, decrypt_file
)

CONFIG_DIR  = Path.home() / ".config" / "msg"
CONFIG_FILE = CONFIG_DIR / "config.ini"
KEY_FILE    = CONFIG_DIR / "private.pem"
LOCK_FILE   = CONFIG_DIR / "session.lock"
DOWNLOADS_DIR = Path.home() / "msg_downloads"
INSTALL_DIR   = Path.home() / ".local" / "lib" / "msg"

# ── Couleurs (désactivées en mode silencieux) ──────────────────────────────────
def _colors_on():
    return {
        "R": "\033[0m", "CYAN": "\033[96m", "GREEN": "\033[92m",
        "RED": "\033[91m", "YELLOW": "\033[93m", "BOLD": "\033[1m", "DIM": "\033[2m"
    }

def _colors_off():
    return {k: "" for k in ["R","CYAN","GREEN","RED","YELLOW","BOLD","DIM"]}

_C = _colors_on()   # couleurs actives par défaut

def set_silent(on: bool):
    global _C
    _C = _colors_off() if on else _colors_on()

def cprint(text, color="R"):
    c = _C.get(color, "")
    r = _C["R"]
    print(f"{c}{text}{r}")


# ── Config ─────────────────────────────────────────────────────────────────────

def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE)
    return cfg


def save_config(cfg: configparser.ConfigParser):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        cfg.write(f)


def is_configured() -> bool:
    cfg = load_config()
    return cfg.has_section("user") and cfg.has_option("user", "username")


def get_ws_url(cfg) -> str:
    host = cfg.get("server", "host", fallback="127.0.0.1")
    port = cfg.get("server", "port", fallback="9999")
    if "onrender.com" in host or host.startswith("wss://") or host.startswith("ws://"):
        base = host if host.startswith("ws") else f"wss://{host}"
    else:
        base = f"ws://{host}:{port}"
    if not base.endswith("/ws"):
        base = base.rstrip("/") + "/ws"
    return base


def load_private_key():
    if not KEY_FILE.exists():
        cprint("✗ Clé privée introuvable. Lance 'msg setup'", "RED")
        sys.exit(1)
    with open(KEY_FILE, "rb") as f:
        return deserialize_private_key(f.read())


# ── Verrouillage local ─────────────────────────────────────────────────────────

def _session_valid() -> bool:
    """Vérifie si la session locale est encore valide (15 min)."""
    if not LOCK_FILE.exists():
        return False
    try:
        ts = float(LOCK_FILE.read_text().strip())
        return (time.time() - ts) < 900  # 15 minutes
    except Exception:
        return False


def _refresh_session():
    """Renouvelle le timestamp de session."""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOCK_FILE.write_text(str(time.time()))
    os.chmod(LOCK_FILE, 0o600)


def _clear_session():
    if LOCK_FILE.exists():
        LOCK_FILE.unlink()


def require_local_auth():
    """Demande le mot de passe local si la session a expiré."""
    if _session_valid():
        _refresh_session()
        return

    cfg      = load_config()
    stored   = cfg.get("user", "password", fallback=None)
    if not stored:
        return  # pas encore configuré

    for attempt in range(3):
        try:
            pwd = getpass.getpass(f"{_C['CYAN']}Mot de passe MSG{_C['R']} : ")
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if pwd == stored:
            _refresh_session()
            return
        else:
            cprint(f"✗ Incorrect ({2 - attempt} essai(s) restant(s))", "RED")

    cprint("✗ Trop de tentatives.", "RED")
    sys.exit(1)


def get_prompt(cfg) -> str:
    """Retourne le prompt du mode interactif (personnalisable)."""
    return cfg.get("display", "prompt", fallback="msg>")


# ── WebSocket helper ───────────────────────────────────────────────────────────

async def ws_call(url: str, packets: list) -> list:
    responses = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(url, timeout=aiohttp.ClientWSTimeout(ws_close=10)) as ws:
                for pkt in packets:
                    await ws.send_json(pkt)
                    raw = await asyncio.wait_for(ws.receive(), timeout=15)
                    if raw.type == aiohttp.WSMsgType.TEXT:
                        responses.append(json.loads(raw.data))
                    else:
                        cprint(f"✗ Erreur connexion", "RED")
                        sys.exit(1)
    except aiohttp.ClientConnectorError as e:
        cprint(f"✗ Impossible de se connecter : {e}", "RED")
        sys.exit(1)
    except asyncio.TimeoutError:
        cprint("✗ Timeout — serveur injoignable.", "RED")
        sys.exit(1)
    return responses


def call(url: str, packets: list) -> list:
    return asyncio.run(ws_call(url, packets))


def auth_packets(cfg) -> list:
    return [{"action": "login",
             "username": cfg.get("user", "username"),
             "password": cfg.get("user", "password")}]


# ── Affichage des messages ─────────────────────────────────────────────────────

def _display_messages(messages, private_key, show_direction=False, my_username=None):
    DOWNLOADS_DIR.mkdir(exist_ok=True)
    for m in messages:
        date   = m["date"][:16]
        sender = m["from"]
        status = f" {_C['GREEN']}●{_C['R']}" if not m.get("read", True) else ""
        sd_tag = f" {_C['YELLOW']}[autodestruct]{_C['R']}" if m.get("self_destruct") else ""

        # Flèche pour mode conversation
        if show_direction and my_username:
            arrow = f"{_C['GREEN']}▶{_C['R']}" if sender == my_username else f"{_C['CYAN']}◀{_C['R']}"
            who   = "moi" if sender == my_username else f"@{sender}"
            header = f"  {arrow} {_C['BOLD']}{who}{_C['R']} {_C['DIM']}[{date}]{_C['R']}{sd_tag}"
        else:
            header = f"  {_C['CYAN']}[{date}]{_C['R']} {_C['BOLD']}@{sender}{_C['R']}{status}{sd_tag}"

        try:
            if m["type"] == "text":
                content = decrypt_message(m["content"], private_key)
                print(header)
                print(f"  {content}\n")
            elif m["type"] in ("file", "image"):
                filename, data = decrypt_file(m["content"].encode(), private_key)
                dest = DOWNLOADS_DIR / filename
                with open(dest, "wb") as f:
                    f.write(data)
                icon = "🖼" if m["type"] == "image" else "📎"
                print(header)
                print(f"  {icon} {_C['GREEN']}{dest}{_C['R']}\n")
        except Exception:
            print(f"{header} {_C['RED']}[illisible]{_C['R']}\n")


# ── Commandes ──────────────────────────────────────────────────────────────────

def cmd_setup():
    cprint(f"\n{_C['BOLD']}── Configuration MSG ──{_C['R']}", "CYAN")

    cfg = configparser.ConfigParser()

    print(f"\n{_C['DIM']}Adresse du serveur{_C['R']}")
    print(f"  {_C['DIM']}• Local     : 127.0.0.1{_C['R']}")
    print(f"  {_C['DIM']}• Render    : mon-app.onrender.com{_C['R']}")
    host = input(f"{_C['CYAN']}Serveur{_C['R']} : ").strip()
    if not host:
        host = "127.0.0.1"

    if "onrender.com" in host or host.startswith("ws"):
        port = "443"
    else:
        port = input(f"{_C['CYAN']}Port{_C['R']} [9999] : ").strip() or "9999"

    cfg["server"] = {"host": host, "port": port}

    print(f"\n{_C['DIM']}Création de ton compte{_C['R']}")
    username = input(f"{_C['CYAN']}Pseudo{_C['R']} (lettres/chiffres, 3-20 car.) : ").strip().lower()
    password = getpass.getpass(f"{_C['CYAN']}Mot de passe{_C['R']} : ")
    password2 = getpass.getpass(f"{_C['CYAN']}Confirme{_C['R']} : ")

    if password != password2:
        cprint("✗ Les mots de passe ne correspondent pas.", "RED")
        sys.exit(1)

    cfg["user"] = {"username": username, "password": password}

    # Prompt personnalisable
    print(f"\n{_C['DIM']}Prompt du mode interactif (défaut: msg>){_C['R']}")
    prompt = input(f"{_C['CYAN']}Prompt{_C['R']} [msg>] : ").strip() or "msg>"
    cfg["display"] = {"prompt": prompt}

    cprint("\n⚙  Génération des clés...", "YELLOW")
    private_key, public_key = generate_keypair()
    pub_pem  = serialize_public_key(public_key)
    priv_pem = serialize_private_key(private_key)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(KEY_FILE, "wb") as f:
        f.write(priv_pem)
    os.chmod(KEY_FILE, 0o600)
    save_config(cfg)

    cprint("↑  Enregistrement...", "YELLOW")
    url = get_ws_url(cfg)
    resp = call(url, [{"action": "register", "username": username,
                       "password": password, "public_key": pub_pem}])[0]

    if resp.get("ok"):
        cprint(f"\n✓ {resp['msg']}", "GREEN")
        cprint(f"  Config : {CONFIG_FILE}", "DIM")
    else:
        cprint(f"\n✗ {resp.get('error', 'Erreur')}", "RED")
        sys.exit(1)


def cmd_send(args, self_destruct=False):
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", "RED"); return
    if not args:
        cprint(f"Usage : msg @pseudo \"message\"", "YELLOW")
        cprint(f"        msg @pseudo fichier.pdf", "YELLOW"); return

    recipient   = args[0].lstrip("@").lower()
    content_arg = " ".join(args[1:]) if len(args) > 1 else None

    if not content_arg:
        cprint("Usage : msg @pseudo \"message\"", "YELLOW"); return

    cfg      = load_config()
    url      = get_ws_url(cfg)
    username = cfg.get("user", "username")
    password = cfg.get("user", "password")

    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "get_pubkey", "username": recipient}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", "RED"); return
    if not responses[1].get("ok"):
        cprint(f"✗ {responses[1].get('error')}", "RED"); return

    recipient_pubkey = deserialize_public_key(responses[1]["public_key"])

    file_path = Path(content_arg)
    if file_path.exists() and file_path.is_file():
        cprint(f"↑  Chiffrement de {file_path.name}...", "YELLOW")
        encrypted = encrypt_file(str(file_path), recipient_pubkey)
        mime = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        msg_type = "image" if mime.startswith("image") else "file"
        pkt = {"action": "send", "to": recipient, "content": encrypted.decode(),
               "type": msg_type, "filename": file_path.name, "self_destruct": self_destruct}
    else:
        encrypted = encrypt_message(content_arg, recipient_pubkey)
        pkt = {"action": "send", "to": recipient, "content": encrypted,
               "type": "text", "self_destruct": self_destruct}

    resp = call(url, [
        {"action": "login", "username": username, "password": password},
        pkt
    ])[1]

    if resp.get("ok"):
        sd = f" {_C['YELLOW']}(autodestruct){_C['R']}" if self_destruct else ""
        cprint(f"✓ {resp['msg']}{sd}", "GREEN")
    else:
        cprint(f"✗ {resp.get('error', 'Erreur')}", "RED")


def cmd_list(args):
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", "RED"); return

    cfg         = load_config()
    url         = get_ws_url(cfg)
    username    = cfg.get("user", "username")
    password    = cfg.get("user", "password")
    private_key = load_private_key()

    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "list", "unread_only": False},
        {"action": "mark_read"}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", "RED"); return

    messages = responses[1].get("messages", [])
    if not messages:
        cprint("Aucun message.", "DIM"); return

    unread = [m for m in messages if not m["read"]]
    read   = [m for m in messages if m["read"]]

    if unread:
        cprint(f"\n{_C['BOLD']}── Nouveaux ({len(unread)}) ──{_C['R']}", "CYAN")
        _display_messages(unread, private_key)
    if read:
        cprint(f"\n{_C['DIM']}── Anciens ({len(read)}) ──{_C['R']}", "DIM")
        _display_messages(read, private_key)


def cmd_unread(args):
    """Affiche uniquement les messages non lus."""
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", "RED"); return

    cfg         = load_config()
    url         = get_ws_url(cfg)
    username    = cfg.get("user", "username")
    password    = cfg.get("user", "password")
    private_key = load_private_key()

    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "unread"}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", "RED"); return

    messages = responses[1].get("messages", [])
    count    = responses[1].get("count", 0)

    if not messages:
        cprint("Aucun nouveau message.", "DIM"); return

    cprint(f"\n{_C['BOLD']}── {count} nouveau(x) message(s) ──{_C['R']}", "CYAN")
    _display_messages(messages, private_key)

    # Marquer comme lus
    call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "mark_read"}
    ])


def cmd_conversation(args):
    """Affiche la conversation complète avec une personne."""
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", "RED"); return
    if not args:
        cprint("Usage : msg conv @pseudo", "YELLOW"); return

    other       = args[0].lstrip("@").lower()
    cfg         = load_config()
    url         = get_ws_url(cfg)
    username    = cfg.get("user", "username")
    password    = cfg.get("user", "password")
    private_key = load_private_key()

    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "conversation", "with": other}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", "RED"); return

    messages = responses[1].get("messages", [])
    if not messages:
        cprint(f"Aucun échange avec @{other}.", "DIM"); return

    cprint(f"\n{_C['BOLD']}── Conversation avec @{other} ──{_C['R']}", "CYAN")
    _display_messages(messages, private_key, show_direction=True, my_username=username)


def cmd_del(args):
    """Supprime la conversation avec une personne."""
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", "RED"); return
    if not args:
        cprint("Usage : msg del @pseudo", "YELLOW"); return

    other    = args[0].lstrip("@").lower()
    cfg      = load_config()
    url      = get_ws_url(cfg)
    username = cfg.get("user", "username")
    password = cfg.get("user", "password")

    confirm = input(f"Supprimer toute la conversation avec @{other} ? [o/N] ").strip().lower()
    if confirm not in ("o", "oui", "y", "yes"):
        cprint("Annulé.", "DIM"); return

    resp = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "del_conversation", "with": other}
    ])[1]

    if resp.get("ok"):
        cprint(f"✓ {resp['msg']}", "GREEN")
    else:
        cprint(f"✗ {resp.get('error', 'Erreur')}", "RED")


def cmd_contacts(args):
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", "RED"); return

    cfg      = load_config()
    url      = get_ws_url(cfg)
    username = cfg.get("user", "username")
    password = cfg.get("user", "password")

    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "contacts"}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", "RED"); return

    contacts = responses[1].get("contacts", [])
    if not contacts:
        cprint("Aucun contact.", "DIM"); return

    cprint(f"\n{_C['BOLD']}── Contacts ({len(contacts)}) ──{_C['R']}", "CYAN")
    for c in contacts:
        status = f"{_C['GREEN']}● en ligne{_C['R']}" if c["online"] else f"{_C['DIM']}○ hors ligne{_C['R']}"
        print(f"  @{c['username']}  {status}")
    print()


def cmd_online(args):
    """Vérifie si quelqu'un est en ligne."""
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", "RED"); return

    cfg      = load_config()
    url      = get_ws_url(cfg)
    username = cfg.get("user", "username")
    password = cfg.get("user", "password")

    target = args[0].lstrip("@").lower() if args else ""

    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "online", "username": target}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", "RED"); return

    r = responses[1]
    if target:
        status = f"{_C['GREEN']}en ligne ●{_C['R']}" if r.get("online") else f"{_C['DIM']}hors ligne ○{_C['R']}"
        print(f"  @{target} : {status}")
    else:
        users = r.get("online_users", [])
        if not users:
            cprint("Personne en ligne.", "DIM")
        else:
            cprint(f"\n{_C['BOLD']}── En ligne ({len(users)}) ──{_C['R']}", "GREEN")
            for u in users:
                print(f"  @{u} {_C['GREEN']}●{_C['R']}")
        print()


def cmd_interactive():
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", "RED"); return

    cfg    = load_config()
    prompt = get_prompt(cfg)

    while True:
        try:
            line = input(f"{_C['CYAN']}{prompt}{_C['R']} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break

        if not line:
            continue
        if line.lower() in ("exit", "quit", "q"):
            break

        parts = line.split()
        cmd   = parts[0].lower()
        rest  = parts[1:]

        if cmd == "list":
            cmd_list(rest)
        elif cmd == "unread":
            cmd_unread(rest)
        elif cmd in ("conv", "conversation"):
            cmd_conversation(rest)
        elif cmd == "del":
            cmd_del(rest)
        elif cmd == "contacts":
            cmd_contacts(rest)
        elif cmd == "online":
            cmd_online(rest)
        elif cmd == "help":
            cmd_help()
        elif cmd.startswith("@"):
            # Détecter flag autodestruct : @pseudo !texte
            if rest and rest[0] == "!":
                cmd_send([cmd] + rest[1:], self_destruct=True)
            else:
                cmd_send([cmd] + rest)
        else:
            cprint("Commandes : list | unread | conv @pseudo | del @pseudo | @pseudo msg | contacts | online | exit", "DIM")


def cmd_lock(args):
    """Verrouille la session locale immédiatement."""
    _clear_session()
    cprint("✓ Session verrouillée.", "GREEN")


def cmd_update(args):
    """Met à jour MSG depuis GitHub."""
    cprint(f"\n{_C['BOLD']}── Mise à jour MSG ──{_C['R']}", "CYAN")

    repo_url = "https://github.com/jordanwinner/msg"

    # Trouver le dossier source (là où est ce script)
    src_dir = Path(__file__).resolve().parent.parent

    # Si c'est un repo git, on pull
    git_dir = src_dir / ".git"
    if git_dir.exists():
        cprint("↓  Récupération des mises à jour...", "YELLOW")
        result = subprocess.run(["git", "-C", str(src_dir), "pull"], capture_output=True, text=True)
        if result.returncode != 0:
            cprint(f"✗ Erreur git pull : {result.stderr.strip()}", "RED")
            return
        output = result.stdout.strip()
        if "Already up to date" in output or "Déjà à jour" in output:
            cprint("✓ Déjà à jour.", "GREEN")
            return
        cprint(f"  {output}", "DIM")
    else:
        # Cloner dans un dossier temporaire et copier
        import tempfile, shutil
        cprint("↓  Téléchargement...", "YELLOW")
        tmp = tempfile.mkdtemp()
        result = subprocess.run(["git", "clone", "--depth=1", repo_url, tmp],
                                capture_output=True, text=True)
        if result.returncode != 0:
            cprint(f"✗ Erreur : {result.stderr.strip()}", "RED")
            return
        for item in ["client", "server", "common", "requirements.txt", "install.sh"]:
            src = Path(tmp) / item
            dst = INSTALL_DIR / item
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            elif src.is_file():
                shutil.copy2(src, dst)
        shutil.rmtree(tmp)

    # Réinstaller les dépendances
    cprint("⚙  Mise à jour des dépendances...", "YELLOW")
    req = INSTALL_DIR / "requirements.txt"
    if req.exists():
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet",
                        "--user", "--break-system-packages",
                        "-r", str(req)], check=False)

    cprint("✓ MSG mis à jour avec succès !", "GREEN")
    cprint("  Relance ton terminal ou tape 'source ~/.zshrc' pour appliquer.", "DIM")


def cmd_help():
    p = _C
    print(f"""
{p['BOLD']}{p['CYAN']}MSG — Messagerie chiffrée{p['R']}

{p['BOLD']}Configuration{p['R']}
  msg setup                        — première configuration
  msg update                       — mettre à jour MSG
  msg lock                         — verrouiller la session

{p['BOLD']}Messages{p['R']}
  msg                              — mode interactif
  msg list                         — tous les messages reçus
  msg unread                       — messages non lus uniquement
  msg @pseudo "message"            — envoyer un message
  msg @pseudo fichier.pdf          — envoyer un fichier/image
  msg burn @pseudo "message"       — message autodestruct
  msg conv @pseudo                 — conversation complète
  msg del @pseudo                  — supprimer une conversation

{p['BOLD']}Contacts & statut{p['R']}
  msg contacts                     — contacts + statut en ligne
  msg online                       — qui est en ligne
  msg online @pseudo               — voir si quelqu'un est en ligne

{p['BOLD']}Mode interactif{p['R']}
  list | unread | conv @x | del @x
  @pseudo message                  — envoyer
  @pseudo ! message                — envoyer autodestruct

{p['BOLD']}Options{p['R']}
  msg --silent [commande]          — mode sans couleur
  msg help                         — cette aide
""")


# ── Point d'entrée ─────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    # Mode silencieux
    if "--silent" in args:
        set_silent(True)
        args = [a for a in args if a != "--silent"]

    if not args:
        # Vérification auth avant mode interactif
        if is_configured():
            require_local_auth()
        cmd_interactive()
        return

    cmd  = args[0].lower()
    rest = args[1:]

    # Ces commandes ne nécessitent pas d'auth locale
    if cmd in ("setup", "update", "help"):
        if cmd == "setup":
            cmd_setup()
        elif cmd == "update":
            cmd_update(rest)
        elif cmd == "help":
            cmd_help()
        return

    # Toutes les autres commandes nécessitent l'auth locale
    if is_configured():
        require_local_auth()

    if cmd == "list":
        cmd_list(rest)
    elif cmd == "unread":
        cmd_unread(rest)
    elif cmd in ("conv", "conversation"):
        cmd_conversation(rest)
    elif cmd == "del":
        cmd_del(rest)
    elif cmd == "contacts":
        cmd_contacts(rest)
    elif cmd == "online":
        cmd_online(rest)
    elif cmd == "burn":
        cmd_send(rest, self_destruct=True)
    elif cmd == "reply":
        cmd_send(rest)
    elif cmd == "lock":
        cmd_lock(rest)
    elif cmd.startswith("@"):
        cmd_send(args)
    else:
        cprint(f"Commande inconnue : {cmd}. Tape 'msg help'", "YELLOW")


if __name__ == "__main__":
    main()
