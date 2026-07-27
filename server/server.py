#!/usr/bin/env python3
"""
Serveur MSG — aiohttp + WebSocket
Sécurité : bcrypt, rate limiting, brute force protection.
"""
import asyncio
import json
import os
import logging
import sqlite3
import time
import hashlib
from collections import defaultdict
from aiohttp import web

try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    USE_BCRYPT = False

DB_PATH = os.environ.get("MSG_DB", os.path.expanduser("~/.msg_server.db"))
PORT    = int(os.environ.get("PORT", 9999))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("msg-server")

# Connexions actives : username -> WebSocket
online_users: dict = {}

# Rate limiting : ip -> [timestamps]
_rate_limit: dict = defaultdict(list)
RATE_WINDOW  = 60   # secondes
RATE_MAX     = 30   # requêtes max par fenêtre
LOGIN_FAILS: dict = defaultdict(list)
LOGIN_MAX    = 5    # tentatives échouées
LOGIN_BAN    = 300  # ban 5 min après


# ── Base de données ────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username     TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            public_key   TEXT NOT NULL,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS messages (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sender       TEXT NOT NULL,
            recipient    TEXT NOT NULL,
            content      TEXT NOT NULL,
            msg_type     TEXT DEFAULT 'text',
            filename     TEXT,
            read         INTEGER DEFAULT 0,
            self_destruct INTEGER DEFAULT 0,
            created_at   TEXT DEFAULT (datetime('now'))
        );
    """)
    try:
        db.execute("ALTER TABLE messages ADD COLUMN self_destruct INTEGER DEFAULT 0")
        db.commit()
    except Exception:
        pass
    db.commit()
    db.close()


def hash_password(password: str) -> str:
    if USE_BCRYPT:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return hashlib.sha256(password.encode()).hexdigest()


def check_password(password: str, hashed: str) -> bool:
    if USE_BCRYPT:
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception:
            # Fallback pour anciens hash SHA256
            return hashlib.sha256(password.encode()).hexdigest() == hashed
    return hashlib.sha256(password.encode()).hexdigest() == hashed


# ── Rate limiting ──────────────────────────────────────────────────────────────

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    _rate_limit[ip] = [t for t in _rate_limit[ip] if now - t < RATE_WINDOW]
    _rate_limit[ip].append(now)
    return len(_rate_limit[ip]) > RATE_MAX


def is_login_banned(ip: str) -> bool:
    now = time.time()
    LOGIN_FAILS[ip] = [t for t in LOGIN_FAILS[ip] if now - t < LOGIN_BAN]
    return len(LOGIN_FAILS[ip]) >= LOGIN_MAX


def record_login_fail(ip: str):
    LOGIN_FAILS[ip].append(time.time())
    remaining = LOGIN_MAX - len(LOGIN_FAILS[ip])
    log.warning(f"Échec login depuis {ip} ({len(LOGIN_FAILS[ip])}/{LOGIN_MAX})")
    return max(0, remaining)


# ── Health check ───────────────────────────────────────────────────────────────

async def handle_health(request):
    return web.Response(text="MSG server OK\n")


# ── Handler WebSocket ──────────────────────────────────────────────────────────

async def handle_ws(request):
    ip = request.remote

    if is_rate_limited(ip):
        log.warning(f"Rate limit dépassé : {ip}")
        return web.Response(status=429, text="Too many requests\n")

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    username = None

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
                    username = await do_register(ws, packet, ip)
                elif action == "login":
                    username = await do_login(ws, packet, ip)
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

async def do_register(ws, packet, ip=""):
    username   = packet.get("username", "").strip().lower()
    password   = packet.get("password", "")
    public_key = packet.get("public_key", "")

    if not username or not password or not public_key:
        await ws.send_json({"ok": False, "error": "Champs manquants"}); return None
    if len(username) < 3 or len(username) > 20:
        await ws.send_json({"ok": False, "error": "Pseudo : 3 à 20 caractères"}); return None
    if not username.isalnum():
        await ws.send_json({"ok": False, "error": "Pseudo : lettres et chiffres uniquement"}); return None
    if len(password) < 6:
        await ws.send_json({"ok": False, "error": "Mot de passe : 6 caractères minimum"}); return None

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
        await ws.send_json({"ok": False, "error": "Ce pseudo est déjà pris"}); return None
    finally:
        db.close()


async def do_login(ws, packet, ip=""):
    username = packet.get("username", "").strip().lower()
    password = packet.get("password", "")

    if is_login_banned(ip):
        await ws.send_json({"ok": False, "error": "Trop de tentatives. Réessaie dans 5 min."})
        return None

    db = get_db()
    row = db.execute("SELECT username, password_hash FROM users WHERE username=?", (username,)).fetchone()
    db.close()

    if not row or not check_password(password, row["password_hash"]):
        remaining = record_login_fail(ip)
        msg = "Identifiants incorrects"
        if remaining <= 2:
            msg += f" ({remaining} tentative(s) restante(s))"
        await ws.send_json({"ok": False, "error": msg})
        return None

    log.info(f"Connecté : {username}")
    await ws.send_json({"ok": True, "msg": f"Connecté en tant que {username}"})
    return username


async def do_send(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    recipient     = packet.get("to", "").strip().lower()
    content       = packet.get("content", "")
    msg_type      = packet.get("type", "text")
    filename      = packet.get("filename")
    self_destruct = 1 if packet.get("self_destruct") else 0

    if not recipient or not content:
        await ws.send_json({"ok": False, "error": "Destinataire ou contenu manquant"}); return

    # Limite taille contenu (10MB)
    if len(content) > 10 * 1024 * 1024:
        await ws.send_json({"ok": False, "error": "Message trop volumineux (max 10MB)"}); return

    db = get_db()
    row = db.execute("SELECT username FROM users WHERE username=?", (recipient,)).fetchone()
    if not row:
        await ws.send_json({"ok": False, "error": f"Utilisateur '{recipient}' introuvable"})
        db.close(); return

    db.execute(
        "INSERT INTO messages (sender, recipient, content, msg_type, filename, self_destruct) VALUES (?, ?, ?, ?, ?, ?)",
        (username, recipient, content, msg_type, filename, self_destruct)
    )
    db.commit()
    db.close()
    await ws.send_json({"ok": True, "msg": f"Message envoyé à {recipient} ✓"})


async def do_list(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    only_unread = packet.get("unread_only", False)
    db  = get_db()
    sql = """SELECT id, sender, content, msg_type, filename, read, self_destruct, created_at
             FROM messages WHERE recipient=?"""
    if only_unread:
        sql += " AND read=0"
    sql += " ORDER BY created_at DESC LIMIT 50"

    rows = db.execute(sql, (username,)).fetchall()
    messages = [{
        "id": r["id"], "from": r["sender"], "content": r["content"],
        "type": r["msg_type"], "filename": r["filename"],
        "read": bool(r["read"]), "self_destruct": bool(r["self_destruct"]),
        "date": r["created_at"]
    } for r in rows]

    ids_sd = [r["id"] for r in rows if r["self_destruct"] and r["read"]]
    if ids_sd:
        db.execute(f"DELETE FROM messages WHERE id IN ({','.join('?'*len(ids_sd))})", ids_sd)
        db.commit()
    db.close()
    await ws.send_json({"ok": True, "messages": messages})


async def do_unread(ws, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    db   = get_db()
    rows = db.execute(
        """SELECT id, sender, content, msg_type, filename, self_destruct, created_at
           FROM messages WHERE recipient=? AND read=0 ORDER BY created_at ASC""",
        (username,)
    ).fetchall()
    db.close()

    messages = [{
        "id": r["id"], "from": r["sender"], "content": r["content"],
        "type": r["msg_type"], "filename": r["filename"],
        "self_destruct": bool(r["self_destruct"]), "date": r["created_at"]
    } for r in rows]
    await ws.send_json({"ok": True, "messages": messages, "count": len(messages)})


async def do_conversation(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    other = packet.get("with", "").strip().lower()
    if not other:
        await ws.send_json({"ok": False, "error": "Paramètre 'with' manquant"}); return

    db   = get_db()
    rows = db.execute(
        """SELECT id, sender, recipient, content, msg_type, filename, read, self_destruct, created_at
           FROM messages
           WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
           ORDER BY created_at ASC LIMIT 100""",
        (username, other, other, username)
    ).fetchall()
    db.close()

    messages = [{
        "id": r["id"], "from": r["sender"], "to": r["recipient"],
        "content": r["content"], "type": r["msg_type"], "filename": r["filename"],
        "read": bool(r["read"]), "self_destruct": bool(r["self_destruct"]), "date": r["created_at"]
    } for r in rows]
    await ws.send_json({"ok": True, "messages": messages, "with": other})


async def do_del_conversation(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    other = packet.get("with", "").strip().lower()
    if not other:
        await ws.send_json({"ok": False, "error": "Paramètre 'with' manquant"}); return

    db = get_db()
    db.execute(
        "DELETE FROM messages WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)",
        (username, other, other, username)
    )
    db.commit()
    db.close()
    await ws.send_json({"ok": True, "msg": f"Conversation avec {other} supprimée ✓"})


async def do_contacts(ws, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    db   = get_db()
    rows = db.execute("SELECT username FROM users WHERE username != ?", (username,)).fetchall()
    db.close()

    contacts = [{"username": r["username"], "online": r["username"] in online_users} for r in rows]
    await ws.send_json({"ok": True, "contacts": contacts})


async def do_get_pubkey(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    target = packet.get("username", "").strip().lower()
    db  = get_db()
    row = db.execute("SELECT public_key FROM users WHERE username=?", (target,)).fetchone()
    db.close()

    if not row:
        await ws.send_json({"ok": False, "error": f"Utilisateur '{target}' introuvable"}); return
    await ws.send_json({"ok": True, "public_key": row["public_key"]})


async def do_mark_read(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    db     = get_db()
    msg_id = packet.get("id")
    if msg_id:
        row = db.execute("SELECT self_destruct FROM messages WHERE id=? AND recipient=?", (msg_id, username)).fetchone()
        if row and row["self_destruct"]:
            db.execute("DELETE FROM messages WHERE id=?", (msg_id,))
        else:
            db.execute("UPDATE messages SET read=1 WHERE id=? AND recipient=?", (msg_id, username))
    else:
        db.execute("DELETE FROM messages WHERE recipient=? AND self_destruct=1", (username,))
        db.execute("UPDATE messages SET read=1 WHERE recipient=?", (username,))
    db.commit()
    db.close()
    await ws.send_json({"ok": True})


async def do_online(ws, packet, username):
    if not username:
        await ws.send_json({"ok": False, "error": "Non authentifié"}); return

    target = packet.get("username", "").strip().lower()
    if target:
        await ws.send_json({"ok": True, "username": target, "online": target in online_users})
    else:
        await ws.send_json({"ok": True, "online_users": list(online_users.keys())})


# ── Main ───────────────────────────────────────────────────────────────────────

async def main():
    init_db()

    app = web.Application()
    app.router.add_get("/",    handle_health)
    app.router.add_get("/ws",  handle_ws)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()

    log.info(f"Serveur MSG démarré sur 0.0.0.0:{PORT}")
    log.info(f"Base de données : {DB_PATH}")
    log.info(f"bcrypt : {'activé' if USE_BCRYPT else 'désactivé (pip install bcrypt)'}")

    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
