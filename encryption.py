from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 
from cryptography.hazmat.primitives.asymmetric import x25519
import os

def generate_key():
     private_key = x25519.X25519PrivateKey.generate()
     public_key = private_key.public_key().public_bytes_raw()
     return private_key, public_key

def share_key(private_key: x25519.X25519PrivateKey, peer_public_bytes: bytes) -> bytes:   
     peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
     shared_key = private_key.exchange(peer_public)

     return shared_key

def encrypt_messages(key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
     nonce = os.urandom(12) 
     aead = ChaCha20Poly1305(key)
     ct = aead.encrypt(nonce, plaintext, aad)
     return nonce + ct

def decrypt_messages(key: bytes, data: bytes, aad: bytes = None) -> bytes:
     if len(data) < 12:
          raise ValueError("data too short")
     nonce, ct = data[:12], data[12:]
     aead = ChaCha20Poly1305(key)
     return aead.decrypt(nonce, ct, aad)

