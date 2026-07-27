#!/usr/bin/env python3
"""
Serveur MSG — aiohttp + WebSocket
Nouvelles fonctionnalités : statut en ligne, accusé de lecture, autodestruction,
suppression de conversation, messages non lus, conversation par personne.
"""
import asyncio
import json
import hashlib
import os
import logging
import sqlite3
import time
from aiohttp import web

DB_PATH = os.environ.get("MSG_DB", os.path.expanduser("~/.msg_server.db"))
PORT = int(os.environ.get("PORT", 9999))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("msg-server")

# Connexions actives : username -> WebSocket (pour statut en ligne)
online_users: dict = {}


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
            self_destruct INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    # Migration : ajouter self_destruct si la colonne n'existe pas encore
    try:
        db.execute("ALTER TABLE messages ADD COLUMN self_destruct INTEGER DEFAULT 0")
        db.commit()
    except Exception:
        pass
    db.commit()
    db.close()


def hash_password(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()


# ── Health check ───────────────────────────────────────────────────────────────

async def handle_health(request):
    return web.Response(text="MSG server OK\n")


# ── Handler WebSocket ──────────────────────────────────────────────────────────

async def handle_ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    username = None
    log.info(f"Connexion : {request.remote}")

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
                    if username:
                        online_users[username] = ws
                elif action == "send":
                    await do_send(ws, packet, username)
                elif action == "list":
                    await do_list(ws, packet, username)
                elif action == "unread":
                    await do_unread(ws, username)
                elif action == "conversation":
                    await do_conversation(ws, packet, username)
                elif action == "del_conversation":
                    await do_del_conversation(ws, packet, username)
                elif action == "contacts":
                    await do_contacts(ws, username)
                elif action == "get_pubkey":
                    await do_get_pubkey(ws, packet, username)
                elif action == "mark_read":
                    await do_mark_read(ws, packet, username)
                elif action == "online":
                    await do_online(ws, packet, username)
                else:
                    await ws.send_json({"ok": False, "error": "Action inconnue"})

            elif msg.type == web.WSMsgType.ERROR:
                break

    except Exception as e:
        log.error(f"Erreur : {e}")
    finally:
        if username and online_users.get(username) is ws:
            del online_users[username]
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
    self_destruct = 1 if packet.get("self_destruct") else 0

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
        "INSERT INTO messages (sender, recipient, content, msg_type, filename, self_destruct) VALUES (?, ?, ?, ?, ?, ?)",
        (username, recipient, content, msg_type, filename, self_destruct)
    )
    db.commit()
    db.close()
    await ws.send_json({"ok": True, "msg": f"Message envoyé à {recipient} ✓"})


async def do_list(ws, packet, username):
    """Tous les messages reçus (unread=False pour tous, True pour non lus seulement)."""
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    only_unread = packet.get("unread_only", False)

    db = get_db()
    query = """SELECT id, sender, content, msg_type, filename, read, self_destruct, created_at
               FROM messages WHERE recipient=?"""
    if only_unread:
        query += " AND read=0"
    query += " ORDER BY created_at DESC LIMIT 50"

    rows = db.execute(query, (username,)).fetchall()

    messages = [{
        "id": r["id"],
        "from": r["sender"],
        "content": r["content"],
        "type": r["msg_type"],
        "filename": r["filename"],
        "read": bool(r["read"]),
        "self_destruct": bool(r["self_destruct"]),
        "date": r["created_at"]
    } for r in rows]

    # Supprimer les messages autodestruct déjà lus
    ids_to_delete = [r["id"] for r in rows if r["self_destruct"] and r["read"]]
    if ids_to_delete:
        db.execute(f"DELETE FROM messages WHERE id IN ({','.join('?'*len(ids_to_delete))})", ids_to_delete)
        db.commit()

    db.close()
    await ws.send_json({"ok": True, "messages": messages})


async def do_unread(ws, username):
    """Messages non lus uniquement."""
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    db = get_db()
    rows = db.execute(
        """SELECT id, sender, content, msg_type, filename, self_destruct, created_at
           FROM messages WHERE recipient=? AND read=0
           ORDER BY created_at ASC""",
        (username,)
    ).fetchall()
    db.close()

    messages = [{
        "id": r["id"],
        "from": r["sender"],
        "content": r["content"],
        "type": r["msg_type"],
        "filename": r["filename"],
        "self_destruct": bool(r["self_destruct"]),
        "date": r["created_at"]
    } for r in rows]

    await ws.send_json({"ok": True, "messages": messages, "count": len(messages)})


async def do_conversation(ws, packet, username):
    """Tous les échanges avec une personne dans l'ordre chronologique."""
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    other = packet.get("with", "").strip().lower()
    if not other:
        await ws.send_json({"ok": False, "error": "Paramètre 'with' manquant"})
        return

    db = get_db()
    rows = db.execute(
        """SELECT id, sender, recipient, content, msg_type, filename, read, self_destruct, created_at
           FROM messages
           WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
           ORDER BY created_at ASC LIMIT 100""",
        (username, other, other, username)
    ).fetchall()
    db.close()

    messages = [{
        "id": r["id"],
        "from": r["sender"],
        "to": r["recipient"],
        "content": r["content"],
        "type": r["msg_type"],
        "filename": r["filename"],
        "read": bool(r["read"]),
        "self_destruct": bool(r["self_destruct"]),
        "date": r["created_at"]
    } for r in rows]

    await ws.send_json({"ok": True, "messages": messages, "with": other})


async def do_del_conversation(ws, packet, username):
    """Supprime tous les messages entre l'utilisateur et une autre personne."""
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    other = packet.get("with", "").strip().lower()
    if not other:
        await ws.send_json({"ok": False, "error": "Paramètre 'with' manquant"})
        return

    db = get_db()
    db.execute(
        """DELETE FROM messages
           WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)""",
        (username, other, other, username)
    )
    db.commit()
    db.close()
    await ws.send_json({"ok": True, "msg": f"Conversation avec {other} supprimée ✓"})


async def do_contacts(ws, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    db = get_db()
    rows = db.execute(
        "SELECT username FROM users WHERE username != ?", (username,)
    ).fetchall()
    db.close()

    contacts = []
    for r in rows:
        contacts.append({
            "username": r["username"],
            "online": r["username"] in online_users
        })

    await ws.send_json({"ok": True, "contacts": contacts})


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
        row = db.execute("SELECT self_destruct FROM messages WHERE id=? AND recipient=?", (msg_id, username)).fetchone()
        if row and row["self_destruct"]:
            db.execute("DELETE FROM messages WHERE id=?", (msg_id,))
        else:
            db.execute("UPDATE messages SET read=1 WHERE id=? AND recipient=?", (msg_id, username))
    else:
        # Supprimer les autodestruct, marquer les autres comme lus
        db.execute("DELETE FROM messages WHERE recipient=? AND self_destruct=1", (username,))
        db.execute("UPDATE messages SET read=1 WHERE recipient=?", (username,))
    db.commit()
    db.close()
    await ws.send_json({"ok": True})


async def do_online(ws, packet, username):
    """Vérifie si un ou plusieurs utilisateurs sont en ligne."""
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"})
        return

    target = packet.get("username", "").strip().lower()
    if target:
        await ws.send_json({"ok": True, "username": target, "online": target in online_users})
    else:
        await ws.send_json({"ok": True, "online_users": list(online_users.keys())})


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
