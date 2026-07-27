# MSG — Messagerie chiffrée dans le terminal

Messagerie end-to-end chiffrée, discrète, qui tourne entièrement dans le terminal.
Chiffrement RSA + AES-256-GCM. Le serveur ne voit jamais tes messages en clair.
Hébergement gratuit sur Render.com — fonctionne même si ton PC est éteint.

---

## Installation rapide

```bash
git clone https://github.com/TON-PSEUDO/msg
cd msg
chmod +x install.sh
./install.sh
```

Puis configure ton compte :

```bash
msg setup
# Serveur : mon-app.onrender.com   ← URL Render
# Pseudo  : jordan
# Mot de passe : ****
```

---

## Déployer le serveur sur Render (gratuit, sans carte)

1. Crée un compte sur [render.com](https://render.com) avec ton GitHub
2. Pousse ce repo sur GitHub
3. Sur Render → **New Web Service** → connecte ton repo
4. Render détecte automatiquement `render.yaml` et configure tout
5. Clique **Deploy** — ton URL sera `https://msg-server.onrender.com`

Donne cette URL à tes amis lors du `msg setup`.

> **Note :** Sur le plan gratuit Render, le serveur s'endort après 15 min d'inactivité.
> Pour éviter ça, ajoute cette ligne dans ton `.zshrc` :
> ```bash
> # Garder le serveur MSG éveillé
> alias msg-keepalive='while true; do curl -s https://TON-APP.onrender.com > /dev/null; sleep 600; done &'
> ```

---

## Commandes

```bash
msg                          # mode interactif discret
msg list                     # voir les messages reçus
msg @pseudo "texte"          # envoyer un message
msg @pseudo fichier.pdf      # envoyer un fichier
msg @pseudo photo.png        # envoyer une image
msg reply @pseudo "texte"    # répondre
msg contacts                 # voir les contacts
msg help                     # aide
```

### Mode interactif

```bash
msg
msg> list
msg> @jordan salut ça va ?
msg> contacts
msg> exit
```

---

## Sécurité

- **RSA 2048** : chaque utilisateur a une paire de clés générée localement
- **AES-256-GCM** : messages chiffrés avant envoi, le serveur ne peut pas les lire
- Fichiers et images également chiffrés
- Clé privée stockée uniquement sur ton PC (`~/.config/msg/private.pem`)

---

## Fichiers reçus

Sauvegardés automatiquement dans `~/msg_downloads/`
