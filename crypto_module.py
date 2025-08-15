# crypto_module.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# RSA key functions
def create_rsa_keys(key_size=2048):
    """Generate an RSA public/private key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_pubkey(pub_key):
    """Convert a public key to PEM format."""
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_pubkey(pem_data):
    """Load a public key from PEM data."""
    return serialization.load_pem_public_key(pem_data)

# AES key functions
def create_aes_key():
    """Generate an AES-256 key (Fernet)."""
    return Fernet.generate_key()

def get_fernet(key):
    """Return a Fernet object from a key."""
    return Fernet(key)

# Encryption / Decryption
def rsa_encrypt(public_key, message_bytes):
    return public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
