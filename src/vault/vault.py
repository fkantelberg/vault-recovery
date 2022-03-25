import base64
import json
import os
import secrets
import sys
from contextlib import contextmanager
from getpass import getpass

from cryptography.hazmat.primitives import hashes, serialization
from psycopg2 import connect
from psycopg2.errors import UndefinedTable
from psycopg2.extras import DictCursor

from . import utils

# The required tables in the database
Tables = [
    "res_users",
    "res_users_key",
    "vault",
    "vault_entry",
    "vault_field",
    "vault_file",
    "vault_right",
]


class Vault:
    def __init__(self, verbose=False):
        self.conn = None
        self.verbose = verbose

    def connect(self, **kwargs):
        self.conn = connect(**{k: v for k, v in kwargs.items() if v is not None})
        return self.check_database()

    @contextmanager
    def cursor(self):
        with self.conn.cursor(cursor_factory=DictCursor) as cr:
            yield cr

    def check_database(self):
        with self.cursor() as cr:
            try:
                for table in sorted(Tables):
                    cr.execute(f"SELECT COUNT(*) FROM {table}")
                    (count,) = cr.fetchone()
                    if self.verbose:
                        utils.info(f"{count} records in {table}")
                return True
            except UndefinedTable:
                return False

    def list_user_keys(self, user_uuid=None):
        """List all available user keys"""
        with self.cursor() as cr:
            query = """
                SELECT k.uuid, u.login, k.fingerprint
                FROM res_users_key AS k
                LEFT JOIN res_users AS u
                ON u.id = k.user_id
                WHERE k.current = true"""

            if user_uuid:
                query += " AND k.uuid = %s"

            cr.execute(query, (user_uuid,))
            return list(map(dict, cr.fetchall()))

    def list_vaults(self, uuuid=None, vuuid=None):
        """List all available vaults of the database"""
        with self.cursor() as cr:
            query = """
                SELECT v.uuid, v.name, k.uuid AS user
                FROM res_users_key AS k
                LEFT JOIN res_users AS u ON u.id = k.user_id
                JOIN vault_right AS r ON r.user_id = u.id
                LEFT JOIN vault AS v ON v.id = r.vault_id"""

            if uuuid and vuuid:
                query += " WHERE k.uuid = %s AND v.uuid = %s"
                args = (uuuid, vuuid)
            elif uuuid:
                query += " WHERE k.uuid = %s"
                args = (uuuid,)
            elif vuuid:
                query += " WHERE v.uuid = %s"
                args = (vuuid,)
            else:
                args = None

            cr.execute(query, args)

            data = {}
            for v in cr.fetchall():
                if v["uuid"] not in data:
                    data[v["uuid"]] = {"name": v["name"], "users": set()}
                data[v["uuid"]]["users"].add(v["user"])
            return data

    def getpass(self, password, passfile):
        passwd = ""
        if password:
            passwd = getpass("Please enter the password: ", stream=sys.stderr)

        if passfile:
            hasher = hashes.Hash(utils.Hash())
            hasher.update(passfile.read())
            passwd += base64.b64encode(hasher.finalize()).decode()

        return passwd

    def extract_private_key(self, key_uuid):
        """Extract information about the key from the database"""
        with self.cursor() as cr:
            cr.execute(
                """
                SELECT k.iv, k.fingerprint, k.salt, k.iterations, k.private, u.login
                FROM res_users_key AS k
                LEFT JOIN res_users AS u ON u.id = k.user_id
                WHERE k.uuid = %s AND k.current = true""",
                (key_uuid,),
            )
            return dict(cr.fetchone()) if cr.rowcount else {}

    def _extract_files(self, cr, entry_id):
        """Extract all files of the given entry"""
        cr.execute(
            """
            SELECT id, name, iv, value, create_date, write_date
            FROM vault_file WHERE entry_id = %s""",
            (entry_id,),
        )
        files = list(map(dict, cr.fetchall()))
        for file in files:
            file["value"] = bytes(file["value"])
        return files

    def _extract_fields(self, cr, entry_id):
        """Extract all fields of the given entry"""
        cr.execute(
            """
            SELECT id, name, iv, value, create_date, write_date
            FROM vault_field WHERE entry_id = %s""",
            (entry_id,),
        )
        return list(map(dict, cr.fetchall()))

    def _extract_entries(self, cr, vault_id, parent_id=None):
        """Extract all entries of the vault"""
        query = """
            SELECT
                e.id, e.uuid, e.complete_name, e.name,
                e.url, e.note, e.create_date, e.write_date
            FROM vault_entry as e
            LEFT JOIN vault_entry AS p ON e.parent_id = p.id
            WHERE e.vault_id = %s"""

        if parent_id is None:
            query += " AND e.parent_id IS NULL"
            cr.execute(f"{query} AND e.parent_id IS NULL", (vault_id,))
        else:
            cr.execute(f"{query} AND e.parent_id = %s", (vault_id, parent_id))

        return [
            {
                **entry,
                "fields": self._extract_fields(cr, entry["id"]),
                "files": self._extract_files(cr, entry["id"]),
                "childs": self._extract_entries(cr, vault_id, entry["id"]),
            }
            for entry in list(map(dict, cr.fetchall()))
        ]

    def _extract_rights(self, cr, vault_id):
        """Extract all rights of the vault"""
        cr.execute(
            """
            SELECT k.uuid, r.key
            FROM res_users_key AS k
            LEFT JOIN res_users AS u ON u.id = k.user_id
            JOIN vault_right AS r ON r.user_id = u.id
            WHERE r.vault_id = %s AND k.current = true""",
            (vault_id,),
        )
        return {right["uuid"]: right["key"] for right in cr.fetchall()}

    def _extract_vault(self, uuid):
        """Extract the specific vault"""
        with self.cursor() as cr:
            cr.execute(
                """
                SELECT id, uuid, name, note, user_id, create_date, write_date
                FROM vault WHERE uuid = %s""",
                (uuid,),
            )
            if not cr.rowcount:
                return {}

            vault = dict(cr.fetchone())
            vault.update(
                {
                    "entries": self._extract_entries(cr, vault["id"]),
                    "rights": self._extract_rights(cr, vault["id"]),
                }
            )
            return vault

    def extract(self, user_uuid, vault_uuid=None):
        """Extract data from the database and store it in an exported file"""
        vaults = vault_uuid if vault_uuid else self.list_vaults(user_uuid)
        return {
            "type": "exported",
            "uuid": user_uuid,
            "private": self.extract_private_key(user_uuid),
            "vaults": list(map(self._extract_vault, vaults)),
        }

    def _decrypt_entry(self, master_key, entry):
        """Decrypt all entries of the vault"""
        for child in entry.get("childs", []):
            self._decrypt_entry(master_key, child)

        for field in entry.get("fields", []):
            field["value"] = utils.sym_decrypt(
                field.pop("iv"),
                field.pop("value"),
                master_key,
                hash_prefix=True,
            ).decode()

        for file in entry.get("files", []):
            value = file.pop("value", b"")
            if isinstance(value, str):
                value = value.encode()

            file["value"] = utils.sym_decrypt(
                file.pop("iv"),
                value,
                master_key,
                hash_prefix=True,
            ).decode()

    def decrypt_private_key(self, data, password):
        """Request the password to decrypt the private RSA key"""
        utils.info(f"Using key {data['fingerprint']} for {data['login']}")

        secret = utils.derive_key(
            f"{data['login']}|{password}".encode(),
            base64.b64decode(data["salt"]),
            data["iterations"],
        )

        # Decrypt the private key of the user
        private = utils.sym_decrypt(data["iv"], data["private"], secret)

        # Load the private key from the decrypted PEM format
        pem = utils.PEMFormat % base64.b64encode(private)
        return serialization.load_pem_private_key(pem, password=None)

    def _decrypt_master_key(self, data, private_key):
        """Decrypt the master key for the vault"""
        master_key = private_key.decrypt(base64.b64decode(data), padding=utils.Padding)
        return utils.Symmetric(master_key)

    def decrypt(self, data, password):
        """Decrypt an encrypted file and output it as raw"""
        fields = ["data", "iterations", "iv", "salt"]
        if data.get("type") != "encrypted" or not all(map(data.get, fields)):
            return None

        salt = base64.b64decode(data["salt"].encode())
        iv = base64.b64decode(data["iv"].encode())
        key = utils.derive_key(password.encode(), salt, 4000)

        decrypted = utils.sym_decrypt(iv, data["data"], key, True)
        return {
            "type": "raw",
            "data": json.loads(decrypted),
        }

    def recover(self, data, user_uuid, private_key):
        """Recover the vaults using the private key on plain data"""
        key = data.get("rights", {}).get(user_uuid)
        if not key:
            return None

        data.pop("rights", None)
        master_key = self._decrypt_master_key(key, private_key)
        for entry in data.get("entries", []):
            self._decrypt_entry(master_key, entry)

        return {"type": "plain", "data": data}

    def convert_to_raw(self, data):
        """Convert the plain decrypted data to an importable format"""
        if data.get("type") == "plain" and data.get("data"):
            return {"type": "raw", "data": data["data"].get("entries", [])}
        return None

    def save_vault_files(self, data, directory):
        """Takes plain/raw data and saves it inside of the given folder. Each entry
        will be stored in a sub-directory named like the entry's uuid where all files
        are stored"""
        dtype = data.get("type")
        if dtype == "plain":
            entries = data.get("data", {}).get("entries", [])[:]
        elif dtype == "raw":
            entries = data.get("data", [])[:]
        else:
            return

        while entries:
            entry = entries.pop()

            entries.extend(entry.get("childs", []))
            files = entry.get("files", [])
            if not files:
                continue

            path = os.path.join(directory, entry["uuid"])
            os.makedirs(path, exist_ok=True)

            for file in files:
                with open(os.path.join(path, file["name"]), "wb+") as fp:
                    fp.write(base64.b64decode(file["value"]))

    def encrypt(self, data, password=None):
        """Encrypt raw data and output it as encrypted data"""
        if data.get("type") != "raw" or not data.get("data"):
            return None

        salt = secrets.token_bytes(utils.SaltLength)
        iv = secrets.token_bytes(utils.IVLength)
        key = utils.derive_key(password.encode(), salt, 4000)

        content = json.dumps(data["data"], default=utils.serialize)
        encrypted = utils.sym_encrypt(iv, content, key, True)
        return {
            "type": "encrypted",
            "iv": base64.b64encode(iv).decode(),
            "salt": base64.b64encode(salt).decode(),
            "data": encrypted,
            "iterations": 4000,
        }
