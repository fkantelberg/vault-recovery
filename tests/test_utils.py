import base64
import secrets
from datetime import datetime

from vault import utils


def test_symmetric_encryption():
    salt = secrets.token_bytes(utils.SaltLength)
    iv = base64.b64encode(secrets.token_bytes(utils.IVLength)).decode()
    key = utils.derive_key(b"test", salt, 4000)

    data = b"hello world"

    # Check encryption with hash prepended
    encrypted_hashed = utils.sym_encrypt(iv, data, key, True)
    decrypted = utils.sym_decrypt(iv, encrypted_hashed, key, True)
    assert data == decrypted

    # Check encryption without hash prepended
    encrypted_unhashed = utils.sym_encrypt(iv, data, key, False)
    decrypted = utils.sym_decrypt(iv, encrypted_unhashed, key, False)
    assert data == decrypted

    # Hashed cipher text should be longer => sign for the hash
    assert len(encrypted_unhashed) < len(encrypted_hashed)

    # Invalid hash
    invalid = b"0" * utils.HashLength
    encrypted_hashed = utils.sym_encrypt(iv, invalid + data, key, False)
    decrypted = utils.sym_decrypt(iv, encrypted_hashed, key, True)
    assert decrypted is None


def test_serialize():
    assert utils.serialize(datetime(1970, 1, 1)) == "1970-01-01 00:00:00"
    assert utils.serialize(b"hello") == "hello"
