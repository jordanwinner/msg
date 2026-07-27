#!/usr/bin/env python3
"""
Serveur MSG — aiohttp + WebSocket
Compatible Render.com : répond au health check HTTP et aux connexions WebSocket
sur le même port.
"""
import asyncio
import json
import hashlib
import os
import sys
import logging
import sqlite3
from aiohttp import web

DB_PATH = os.environ.get("MSG_DB", os.path.expanduser("~/.msg_server.db"))
PORT = int(os.environ.get("PORT", 9999))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("msg-server")


# ── Base de données ────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            content TEXT NOT NULL,
            msg_type TEXT DEFAULT 'text',
            filename TEXT,
            read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    db.commit()
    db.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ── Health check HTTP ──────────────────────────────────────────────────────────

async def handle_health(request):
    return web.Response(text="MSG server OK\n")


# ── Handler WebSocket ──────────────────────────────────────────────────────────

async def handle_ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    username = None
    log.info(f"Nouvelle connexion : {request.remote}")

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    packet = json.loads(msg.data)
                except json.JSONDecodeError:
                    await ws.send_json({"ok": False, "error": "JSON invalide"})
                    continue

                action = packet.get("action")

                if action == "register":
                    username = await do_register(ws, packet)
                elif action == "login":
                    username = await do_login(ws, packet)
                elif action == "send":
                    await do_send(ws, packet, username)
                elif action == "list":
                    await do_list(ws, username)
                elif action == "contacts":
                    await do_contacts(ws, username)
                elif action == "get_pubkey":
                    await do_get_pubkey(ws, packet, username)
                elif action == "mark_read":
                    await do_mark_read(ws, packet, username)
                else:
                    await ws.send_json({"ok": False, "error": "Action inconnue"})

            elif msg.type == web.WSMsgType.ERROR:
                log.error(f"Erreur WebSocket : {ws.exception()}")
                break

    except Exception as e:
        log.error(f"Erreur client : {e}")
    finally:
        if username:
            log.info(f"Déconnecté : {username}")

    return ws


# ── Actions ────────────────────────────────────────────────────────────────────

async def do_register(ws, packet):
    username = packet.get("username", "").strip().lower()
    password = packet.get("password", "")
    public_key = packet.get("public_key", "")

    if not username or not password or not public_key:
        await ws.send_json({"ok": False, "error": "Champs manquants"})
        return None
    if len(username) < 3 or len(username) > 20:
        await ws.send_json({"ok": False, "error": "Pseudo : 3 à 20 caractères"})
        return None
    if not username.isalnum():
        await ws.send_json({"ok": False, "error": "Pseudo : lettres et chiffres uniquement"})
        return None

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
            (username, hash_password(password), public_key)
        )
        db.commit()
        await ws.send_json({"ok": True, "msg": f"Compte créé. Bienvenue {username} ✓"})
        log.info(f"Nouveau compte : {username}")
        return username
    except sqlite3.IntegrityError:
        await ws.send_json({"ok": False, "error": "Ce pseudo est déjà pris"})
        return None
    finally:
        db.close()


async def do_login(ws, packet):
    username = packet.get("username", "").strip().lower()
    password = packet.get("password", "")

    db = get_db()
    row = db.execute(
        "SELECT username FROM users WHERE username=? AND password_hash=?",
        (username, hash_password(password))
    ).fetchone()
    db.close()

    if not row:
        await ws.send_json({"ok": False, "error": "Identifiants incorrects"})
        return None

    log.info(f"Connecté : {username}")
    await ws.send_json({"ok": True, "msg": f"Connecté en tant que {username}"})
    return username


async def do_send(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    recipient = packet.get("to", "").strip().lower()
    content = packet.get("content", "")
    msg_type = packet.get("type", "text")
    filename = packet.get("filename")

    if not recipient or not content:
        await ws.send_json({"ok": False, "error": "Destinataire ou contenu manquant"})
        return

    db = get_db()
    row = db.execute("SELECT username FROM users WHERE username=?", (recipient,)).fetchone()
    if not row:
        await ws.send_json({"ok": False, "error": f"Utilisateur '{recipient}' introuvable"})
        db.close()
        return

    db.execute(
        "INSERT INTO messages (sender, recipient, content, msg_type, filename) VALUES (?, ?, ?, ?, ?)",
        (username, recipient, content, msg_type, filename)
    )
    db.commit()
    db.close()
    await ws.send_json({"ok": True, "msg": f"Message envoyé à {recipient} ✓"})


async def do_list(ws, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    db = get_db()
    rows = db.execute(
        """SELECT id, sender, content, msg_type, filename, read, created_at
           FROM messages WHERE recipient=?
           ORDER BY created_at DESC LIMIT 50""",
        (username,)
    ).fetchall()
    db.close()

    messages = [{
        "id": r["id"],
        "from": r["sender"],
        "content": r["content"],
        "type": r["msg_type"],
        "filename": r["filename"],
        "read": bool(r["read"]),
        "date": r["created_at"]
    } for r in rows]

    await ws.send_json({"ok": True, "messages": messages})


async def do_contacts(ws, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    db = get_db()
    rows = db.execute(
        "SELECT username FROM users WHERE username != ?", (username,)
    ).fetchall()
    db.close()

    await ws.send_json({"ok": True, "contacts": [r["username"] for r in rows]})


async def do_get_pubkey(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    target = packet.get("username", "").strip().lower()
    db = get_db()
    row = db.execute("SELECT public_key FROM users WHERE username=?", (target,)).fetchone()
    db.close()

    if not row:
        await ws.send_json({"ok": False, "error": f"Utilisateur '{target}' introuvable"})
        return

    await ws.send_json({"ok": True, "public_key": row["public_key"]})


async def do_mark_read(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    db = get_db()
    msg_id = packet.get("id")
    if msg_id:
        db.execute("UPDATE messages SET read=1 WHERE id=? AND recipient=?", (msg_id, username))
    else:
        db.execute("UPDATE messages SET read=1 WHERE recipient=?", (username,))
    db.commit()
    db.close()
    await ws.send_json({"ok": True})


# ── Main ───────────────────────────────────────────────────────────────────────

async def main():
    init_db()

    app = web.Application()
    app.router.add_get("/", handle_health)
    app.router.add_get("/ws", handle_ws)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()

    log.info(f"Serveur MSG démarré sur 0.0.0.0:{PORT}")
    log.info(f"Base de données : {DB_PATH}")
    log.info(f"WebSocket : ws://0.0.0.0:{PORT}/ws")

    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
