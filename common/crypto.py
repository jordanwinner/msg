"""
Chiffrement bout en bout — RSA + AES-256
"""
import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_keypair():
    """Génère une paire de clés RSA 2048 bits."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> str:
    """Convertit une clé publique en string PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def deserialize_public_key(pem: str):
    """Recharge une clé publique depuis une string PEM."""
    return serialization.load_pem_public_key(pem.encode(), backend=default_backend())


def serialize_private_key(private_key, password: bytes = None) -> bytes:
    """Sérialise la clé privée (chiffrée avec mot de passe si fourni)."""
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )


def deserialize_private_key(pem: bytes, password: bytes = None):
    """Recharge une clé privée."""
    return serialization.load_pem_private_key(pem, password=password, backend=default_backend())


def encrypt_message(message: str, recipient_public_key) -> str:
    """
    Chiffre un message pour un destinataire :
    1. Génère une clé AES aléatoire
    2. Chiffre le message avec AES-256-GCM
    3. Chiffre la clé AES avec la clé publique RSA du destinataire
    Retourne un JSON base64.
    """
    # Clé AES et IV aléatoires
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    # Chiffrement AES-GCM
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    tag = encryptor.tag

    # Chiffrement de la clé AES avec RSA
    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    payload = {
        "k": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def decrypt_message(encrypted_payload: str, private_key) -> str:
    """Déchiffre un message avec la clé privée du destinataire."""
    payload = json.loads(base64.b64decode(encrypted_payload).decode())

    encrypted_key = base64.b64decode(payload["k"])
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ct"])
    tag = base64.b64decode(payload["tag"])

    # Déchiffrer la clé AES
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Déchiffrer le message
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()


def encrypt_file(file_path: str, recipient_public_key) -> bytes:
    """Chiffre un fichier pour un destinataire."""
    with open(file_path, "rb") as f:
        data = f.read()

    aes_key = os.urandom(32)
    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag

    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    payload = {
        "k": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "filename": os.path.basename(file_path)
    }
    return base64.b64encode(json.dumps(payload).encode())


def decrypt_file(encrypted_payload: bytes, private_key) -> tuple:
    """Retourne (nom_fichier, données_déchiffrées)."""
    payload = json.loads(base64.b64decode(encrypted_payload).decode())

    encrypted_key = base64.b64decode(payload["k"])
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ct"])
    tag = base64.b64decode(payload["tag"])
    filename = payload["filename"]

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    return filename, data
