#!/usr/bin/env python3
"""
Serveur MSG — WebSocket + HTTP health check pour Render
"""
import asyncio
import websockets
import sqlite3
import json
import hashlib
import os
import sys
import logging
from datetime import datetime
from http.server import BaseHTTPRequestHandler
import threading

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


# ── Handler WebSocket ──────────────────────────────────────────────────────────

async def handle_client(websocket):
    username = None
    log.info(f"Nouvelle connexion : {websocket.remote_address}")

    try:
        async for raw in websocket:
            try:
                packet = json.loads(raw)
            except json.JSONDecodeError:
                await send(websocket, {"ok": False, "error": "JSON invalide"})
                continue

            action = packet.get("action")

            if action == "register":
                username = await do_register(websocket, packet)
            elif action == "login":
                username = await do_login(websocket, packet)
            elif action == "send":
                await do_send(websocket, packet, username)
            elif action == "list":
                await do_list(websocket, username)
            elif action == "contacts":
                await do_contacts(websocket, username)
            elif action == "get_pubkey":
                await do_get_pubkey(websocket, packet, username)
            elif action == "mark_read":
                await do_mark_read(websocket, packet, username)
            else:
                await send(websocket, {"ok": False, "error": "Action inconnue"})

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        log.error(f"Erreur : {e}")
    finally:
        if username:
            log.info(f"Déconnecté : {username}")


async def send(websocket, data: dict):
    await websocket.send(json.dumps(data))


# ── Health check HTTP pour Render ─────────────────────────────────────────────

def health_check(connection, request):
    """
    Répond aux requêtes HTTP normales (health check de Render).
    Si ce n'est pas une upgrade WebSocket, on retourne 200 OK.
    """
    if request.headers.get("Upgrade", "").lower() != "websocket":
        from websockets.http11 import Response
        from websockets.datastructures import Headers
        return Response(
            status_code=200,
            reason_phrase="OK",
            headers=Headers([("Content-Type", "text/plain"), ("Content-Length", "14")]),
            body=b"MSG server OK\n"
        )


# ── Actions ────────────────────────────────────────────────────────────────────

async def do_register(websocket, packet):
    username = packet.get("username", "").strip().lower()
    password = packet.get("password", "")
    public_key = packet.get("public_key", "")

    if not username or not password or not public_key:
        await send(websocket, {"ok": False, "error": "Champs manquants"})
        return None
    if len(username) < 3 or len(username) > 20:
        await send(websocket, {"ok": False, "error": "Pseudo : 3 à 20 caractères"})
        return None
    if not username.isalnum():
        await send(websocket, {"ok": False, "error": "Pseudo : lettres et chiffres uniquement"})
        return None

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
            (username, hash_password(password), public_key)
        )
        db.commit()
        await send(websocket, {"ok": True, "msg": f"Compte créé. Bienvenue {username} ✓"})
        log.info(f"Nouveau compte : {username}")
        return username
    except sqlite3.IntegrityError:
        await send(websocket, {"ok": False, "error": "Ce pseudo est déjà pris"})
        return None
    finally:
        db.close()


async def do_login(websocket, packet):
    username = packet.get("username", "").strip().lower()
    password = packet.get("password", "")

    db = get_db()
    row = db.execute(
        "SELECT username FROM users WHERE username=? AND password_hash=?",
        (username, hash_password(password))
    ).fetchone()
    db.close()

    if not row:
        await send(websocket, {"ok": False, "error": "Identifiants incorrects"})
        return None

    log.info(f"Connecté : {username}")
    await send(websocket, {"ok": True, "msg": f"Connecté en tant que {username}"})
    return username


async def do_send(websocket, packet, username):
    if not username:
        await send(websocket, {"ok": False, "error": "Non authentifié"})
        return

    recipient = packet.get("to", "").strip().lower()
    content = packet.get("content", "")
    msg_type = packet.get("type", "text")
    filename = packet.get("filename")

    if not recipient or not content:
        await send(websocket, {"ok": False, "error": "Destinataire ou contenu manquant"})
        return

    db = get_db()
    row = db.execute("SELECT username FROM users WHERE username=?", (recipient,)).fetchone()
    if not row:
        await send(websocket, {"ok": False, "error": f"Utilisateur '{recipient}' introuvable"})
        db.close()
        return

    db.execute(
        "INSERT INTO messages (sender, recipient, content, msg_type, filename) VALUES (?, ?, ?, ?, ?)",
        (username, recipient, content, msg_type, filename)
    )
    db.commit()
    db.close()
    await send(websocket, {"ok": True, "msg": f"Message envoyé à {recipient} ✓"})


async def do_list(websocket, username):
    if not username:
        await send(websocket, {"ok": False, "error": "Non authentifié"})
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

    await send(websocket, {"ok": True, "messages": messages})


async def do_contacts(websocket, username):
    if not username:
        await send(websocket, {"ok": False, "error": "Non authentifié"})
        return

    db = get_db()
    rows = db.execute(
        "SELECT username FROM users WHERE username != ?", (username,)
    ).fetchall()
    db.close()

    await send(websocket, {"ok": True, "contacts": [r["username"] for r in rows]})


async def do_get_pubkey(websocket, packet, username):
    if not username:
        await send(websocket, {"ok": False, "error": "Non authentifié"})
        return

    target = packet.get("username", "").strip().lower()
    db = get_db()
    row = db.execute("SELECT public_key FROM users WHERE username=?", (target,)).fetchone()
    db.close()

    if not row:
        await send(websocket, {"ok": False, "error": f"Utilisateur '{target}' introuvable"})
        return

    await send(websocket, {"ok": True, "public_key": row["public_key"]})


async def do_mark_read(websocket, packet, username):
    if not username:
        await send(websocket, {"ok": False, "error": "Non authentifié"})
        return

    db = get_db()
    msg_id = packet.get("id")
    if msg_id:
        db.execute("UPDATE messages SET read=1 WHERE id=? AND recipient=?", (msg_id, username))
    else:
        db.execute("UPDATE messages SET read=1 WHERE recipient=?", (username,))
    db.commit()
    db.close()
    await send(websocket, {"ok": True})


# ── Main ───────────────────────────────────────────────────────────────────────

async def main():
    init_db()
    log.info(f"Serveur MSG démarré sur 0.0.0.0:{PORT}")
    log.info(f"Base de données : {DB_PATH}")

    async with websockets.serve(
        handle_client,
        "0.0.0.0",
        PORT,
        process_request=health_check
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
