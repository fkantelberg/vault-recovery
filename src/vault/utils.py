import base64
import json
import logging
import sys
from datetime import datetime
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf import pbkdf2

_logger = logging.getLogger("vault")

HashLength = 10
Hash = hashes.SHA512
IVLength = 12
Iterations = 600_001
Padding = padding.OAEP(
    mgf=padding.MGF1(algorithm=Hash()),
    algorithm=Hash(),
    label=None,
)
PEMFormat = b"-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----"
SaltLength = 32
PrivateKey = rsa.RSAPrivateKey
SharePinSize = 5
Symmetric = algorithms.AES
SymmetricLength = 256
TagLength = 128

IV = str | bytes


def error(msg: str) -> None:
    print(msg, file=sys.stderr)


def info(msg: str) -> None:
    print(msg, file=sys.stderr)


def file_type(mode: str = "r") -> Callable:
    def wrapper(x):
        if x == "-":
            return sys.stdin
        return open(x, mode, encoding="utf-8")

    return wrapper


def serialize(obj: Any) -> str | None:
    """Serialize some values of the database directly"""
    if isinstance(obj, datetime):
        return obj.isoformat(" ")

    if isinstance(obj, bytes):
        return obj.decode()

    return None


def output(content: Any) -> None:
    print(json.dumps(content, indent=2, default=serialize))


def dump_json(filename: str, content: Any) -> None:
    with open(filename, "w+", encoding="utf-8") as fp:
        json.dump(content, fp, sort_keys=True, indent=2, default=serialize)


def derive_key(password: bytes, salt: bytes, iterations: int) -> algorithms.AES:
    """Derive the secret from the password"""
    secret = pbkdf2.PBKDF2HMAC(
        Hash(),
        iterations=iterations,
        length=SymmetricLength >> 3,
        salt=salt,
    ).derive(password)
    # Decrypt the private key of the user
    return Symmetric(secret)


def sym_decrypt(
    iv: IV, value: str, key: algorithms.AES, hash_prefix: bool = False
) -> bytes | None:
    """Wrapper to decrypt a value using the key and iv compatible with
    Web Crypto API"""
    if isinstance(iv, str):
        iv = base64.b64decode(iv)

    encrypted = base64.b64decode(value)
    tag_size = (TagLength + 7) >> 3
    cipher = Cipher(key, modes.GCM(iv, tag=encrypted[-tag_size:]))
    decryptor = cipher.decryptor()

    # Decrypt the value and slice the tag added by the JS crypto API
    decrypted = decryptor.update(encrypted[:-tag_size]) + decryptor.finalize()
    if not hash_prefix:
        return decrypted

    # There is a hash to validate
    stored_hash = decrypted[:HashLength]
    decrypted = decrypted[HashLength:]
    hasher = hashes.Hash(Hash())
    hasher.update(decrypted)
    hashed = base64.b64encode(hasher.finalize())[:HashLength]
    if hashed != stored_hash:
        return None

    return decrypted


def sym_encrypt(
    iv: IV, value: str, key: algorithms.AES, hash_prefix: bool = False
) -> str:
    """Wrapper to encrypt a value using key and iv compatible with
    Web Crypto API"""
    if isinstance(iv, str):
        iv = base64.b64decode(iv)

    cipher = Cipher(key, modes.GCM(iv, min_tag_length=TagLength))
    encryptor = cipher.encryptor()

    content = value if isinstance(value, bytes) else value.encode()
    if hash_prefix:
        hasher = hashes.Hash(Hash())
        hasher.update(content)
        content = base64.b64encode(hasher.finalize())[:HashLength] + content

    encrypted = encryptor.update(content) + encryptor.finalize()
    return base64.b64encode(encrypted + encryptor.tag).decode()
