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
import websockets
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.crypto import (
    generate_keypair, serialize_public_key, serialize_private_key,
    deserialize_private_key, deserialize_public_key,
    encrypt_message, decrypt_message,
    encrypt_file, decrypt_file
)

CONFIG_DIR = Path.home() / ".config" / "msg"
CONFIG_FILE = CONFIG_DIR / "config.ini"
KEY_FILE = CONFIG_DIR / "private.pem"
DOWNLOADS_DIR = Path.home() / "msg_downloads"

# Couleurs
R      = "\033[0m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


def cprint(text, color=R):
    print(f"{color}{text}{R}")


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
    # Si l'host ressemble à une URL Render (*.onrender.com), on utilise wss://
    if "onrender.com" in host or host.startswith("wss://") or host.startswith("ws://"):
        url = host if host.startswith("ws") else f"wss://{host}"
    else:
        url = f"ws://{host}:{port}"
    return url


def load_private_key():
    if not KEY_FILE.exists():
        cprint("✗ Clé privée introuvable. Lance 'msg setup'", RED)
        sys.exit(1)
    with open(KEY_FILE, "rb") as f:
        return deserialize_private_key(f.read())


# ── WebSocket helper ───────────────────────────────────────────────────────────

async def ws_call(url: str, packets: list) -> list:
    """
    Envoie une liste de paquets et retourne les réponses dans l'ordre.
    Ferme la connexion proprement après.
    """
    responses = []
    try:
        async with websockets.connect(url, open_timeout=10) as ws:
            for pkt in packets:
                await ws.send(json.dumps(pkt))
                raw = await asyncio.wait_for(ws.recv(), timeout=15)
                responses.append(json.loads(raw))
    except (websockets.exceptions.WebSocketException, OSError) as e:
        cprint(f"✗ Connexion impossible : {e}", RED)
        sys.exit(1)
    except asyncio.TimeoutError:
        cprint("✗ Timeout — le serveur ne répond pas.", RED)
        sys.exit(1)
    return responses


def call(url: str, packets: list) -> list:
    """Version synchrone de ws_call."""
    return asyncio.run(ws_call(url, packets))


# ── Commandes ──────────────────────────────────────────────────────────────────

def cmd_setup():
    cprint(f"\n{BOLD}── Configuration MSG ──{R}", CYAN)

    cfg = configparser.ConfigParser()

    print(f"\n{DIM}Adresse du serveur{R}")
    print(f"  {DIM}• Local        : 127.0.0.1{R}")
    print(f"  {DIM}• Tailscale    : 100.x.x.x{R}")
    print(f"  {DIM}• Render       : mon-app.onrender.com{R}")
    host = input(f"{CYAN}Serveur{R} : ").strip()
    if not host:
        host = "127.0.0.1"

    # Pour local/Tailscale on demande le port, pour Render non
    if "onrender.com" in host or host.startswith("ws"):
        port = "443"
    else:
        port = input(f"{CYAN}Port{R} [9999] : ").strip() or "9999"

    cfg["server"] = {"host": host, "port": port}

    print(f"\n{DIM}Création de ton compte{R}")
    username = input(f"{CYAN}Pseudo{R} (lettres/chiffres, 3-20 car.) : ").strip().lower()
    password = getpass.getpass(f"{CYAN}Mot de passe{R} : ")
    password2 = getpass.getpass(f"{CYAN}Confirme{R} : ")

    if password != password2:
        cprint("✗ Les mots de passe ne correspondent pas.", RED)
        sys.exit(1)

    cfg["user"] = {"username": username, "password": password}

    # Génération des clés
    cprint("\n⚙  Génération de tes clés de chiffrement...", YELLOW)
    private_key, public_key = generate_keypair()
    pub_pem = serialize_public_key(public_key)
    priv_pem = serialize_private_key(private_key)

    # Sauvegarder localement
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(KEY_FILE, "wb") as f:
        f.write(priv_pem)
    os.chmod(KEY_FILE, 0o600)
    save_config(cfg)

    # Enregistrement sur le serveur
    cprint("↑  Enregistrement sur le serveur...", YELLOW)
    url = get_ws_url(cfg)
    responses = call(url, [{
        "action": "register",
        "username": username,
        "password": password,
        "public_key": pub_pem
    }])
    resp = responses[0]

    if resp.get("ok"):
        cprint(f"\n✓ {resp['msg']}", GREEN)
        cprint(f"  Config : {CONFIG_FILE}", DIM)
        cprint(f"  Clé privée : {KEY_FILE}", DIM)
    else:
        cprint(f"\n✗ {resp.get('error', 'Erreur')}", RED)
        sys.exit(1)


def cmd_send(args):
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", RED)
        return
    if not args:
        cprint(f"Usage : msg @pseudo \"message\"", YELLOW)
        cprint(f"        msg @pseudo fichier.pdf", YELLOW)
        return

    recipient = args[0].lstrip("@").lower()
    content_arg = " ".join(args[1:]) if len(args) > 1 else None

    if not content_arg:
        cprint("Usage : msg @pseudo \"message\"", YELLOW)
        return

    cfg = load_config()
    url = get_ws_url(cfg)
    username = cfg.get("user", "username")
    password = cfg.get("user", "password")

    # Login + récupérer clé publique du destinataire en une session
    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "get_pubkey", "username": recipient}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", RED)
        return
    if not responses[1].get("ok"):
        cprint(f"✗ {responses[1].get('error')}", RED)
        return

    recipient_pubkey = deserialize_public_key(responses[1]["public_key"])

    # Fichier ou texte ?
    file_path = Path(content_arg)
    if file_path.exists() and file_path.is_file():
        cprint(f"↑  Chiffrement de {file_path.name}...", YELLOW)
        encrypted = encrypt_file(str(file_path), recipient_pubkey)
        mime = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        msg_type = "image" if mime.startswith("image") else "file"
        pkt = {
            "action": "send", "to": recipient,
            "content": encrypted.decode(),
            "type": msg_type, "filename": file_path.name
        }
    else:
        encrypted = encrypt_message(content_arg, recipient_pubkey)
        pkt = {"action": "send", "to": recipient, "content": encrypted, "type": "text"}

    responses2 = call(url, [
        {"action": "login", "username": username, "password": password},
        pkt
    ])
    resp = responses2[1]
    if resp.get("ok"):
        cprint(f"✓ {resp['msg']}", GREEN)
    else:
        cprint(f"✗ {resp.get('error', 'Erreur')}", RED)


def cmd_list(args):
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", RED)
        return

    cfg = load_config()
    url = get_ws_url(cfg)
    username = cfg.get("user", "username")
    password = cfg.get("user", "password")
    private_key = load_private_key()

    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "list"},
        {"action": "mark_read"}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", RED)
        return

    messages = responses[1].get("messages", [])
    if not messages:
        cprint("Aucun message.", DIM)
        return

    unread = [m for m in messages if not m["read"]]
    read   = [m for m in messages if m["read"]]

    if unread:
        cprint(f"\n{BOLD}── Nouveaux messages ({len(unread)}) ──{R}", CYAN)
        _display_messages(unread, private_key)
    if read:
        cprint(f"\n{DIM}── Anciens messages ({len(read)}) ──{R}", DIM)
        _display_messages(read, private_key)


def _display_messages(messages, private_key):
    DOWNLOADS_DIR.mkdir(exist_ok=True)
    for m in messages:
        date   = m["date"][:16]
        sender = m["from"]
        status = f" {GREEN}●{R}" if not m["read"] else ""
        try:
            if m["type"] == "text":
                content = decrypt_message(m["content"], private_key)
                print(f"  {CYAN}[{date}]{R} {BOLD}@{sender}{R}{status}")
                print(f"  {content}\n")
            elif m["type"] in ("file", "image"):
                filename, data = decrypt_file(m["content"].encode(), private_key)
                dest = DOWNLOADS_DIR / filename
                with open(dest, "wb") as f:
                    f.write(data)
                icon = "🖼" if m["type"] == "image" else "📎"
                print(f"  {CYAN}[{date}]{R} {BOLD}@{sender}{R}{status}")
                print(f"  {icon} Fichier reçu : {GREEN}{dest}{R}\n")
        except Exception:
            print(f"  {CYAN}[{date}]{R} {BOLD}@{sender}{R} {RED}[illisible]{R}\n")


def cmd_contacts(args):
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", RED)
        return

    cfg = load_config()
    url = get_ws_url(cfg)
    username = cfg.get("user", "username")
    password = cfg.get("user", "password")

    responses = call(url, [
        {"action": "login", "username": username, "password": password},
        {"action": "contacts"}
    ])

    if not responses[0].get("ok"):
        cprint(f"✗ {responses[0].get('error')}", RED)
        return

    contacts = responses[1].get("contacts", [])
    if not contacts:
        cprint("Aucun contact.", DIM)
        return

    cprint(f"\n{BOLD}── Contacts ({len(contacts)}) ──{R}", CYAN)
    for c in contacts:
        print(f"  @{c}")
    print()


def cmd_interactive():
    if not is_configured():
        cprint("✗ Lance d'abord 'msg setup'", RED)
        return

    cprint(f"\n{BOLD}── Mode MSG ──{R} (tape 'exit' pour quitter)\n", CYAN)
    cprint("Commandes : list | @pseudo message | contacts | exit\n", DIM)

    while True:
        try:
            line = input(f"{CYAN}msg>{R} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue
        if line.lower() in ("exit", "quit", "q"):
            break

        parts = line.split()
        cmd   = parts[0].lower()
        rest  = parts[1:]

        if cmd == "list":
            cmd_list(rest)
        elif cmd == "contacts":
            cmd_contacts(rest)
        elif cmd.startswith("@"):
            cmd_send([cmd] + rest)
        else:
            cprint("Commandes : list | @pseudo message | contacts | exit", DIM)


def cmd_help():
    print(f"""
{BOLD}{CYAN}MSG — Messagerie chiffrée{R}

{BOLD}Configuration{R}
  msg setup                   — première configuration

{BOLD}Messages{R}
  msg                         — mode interactif
  msg list                    — voir les messages reçus
  msg @pseudo "message"       — envoyer un message
  msg @pseudo fichier.pdf     — envoyer un fichier
  msg reply @pseudo "texte"   — répondre

{BOLD}Contacts{R}
  msg contacts                — voir les contacts

{BOLD}Aide{R}
  msg help                    — afficher cette aide
""")


# ── Point d'entrée ─────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        cmd_interactive()
        return

    cmd  = args[0].lower()
    rest = args[1:]

    if cmd == "setup":
        cmd_setup()
    elif cmd == "list":
        cmd_list(rest)
    elif cmd == "contacts":
        cmd_contacts(rest)
    elif cmd == "reply":
        cmd_send(rest)
    elif cmd == "help":
        cmd_help()
    elif cmd.startswith("@"):
        cmd_send(args)
    else:
        cprint(f"Commande inconnue : {cmd}. Tape 'msg help'", YELLOW)


if __name__ == "__main__":
    main()
