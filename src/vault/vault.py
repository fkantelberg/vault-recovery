import base64
import json
import os
import secrets
import sys
from contextlib import contextmanager
from getpass import getpass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from psycopg2 import connect
from psycopg2.extras import DictCursor

from . import utils

# The required tables in the database. vault_inbox and vault_share are handled
# optionally
Tables = {
    "res_users": True,
    "res_users_key": True,
    "vault": True,
    "vault_entry": True,
    "vault_field": True,
    "vault_file": True,
    "vault_inbox": False,
    "vault_right": True,
    "vault_share": False,
}

DataList = list[dict]


class Vault:
    def __init__(self, verbose: bool = False):
        self.conn = None
        self.verbose: bool = verbose

    def connect(self, **kwargs: Any) -> bool:
        self.conn = connect(**{k: v for k, v in kwargs.items() if v is not None})
        return self.check_database()

    def exists(self, cr: DictCursor, table: str, column: str | None = None) -> bool:
        """Check if the table (and column) exists in the database"""
        query = """
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
        """

        if column:
            cr.execute(f"{query} AND column_name = %s", (table, column))
        else:
            cr.execute(query, (table,))

        return bool(cr.rowcount)

    @contextmanager
    def cursor(self) -> DictCursor:
        with self.conn.cursor(cursor_factory=DictCursor) as cr:
            yield cr

    def check_database(self) -> bool:
        with self.cursor() as cr:
            for table, required in sorted(Tables.items()):
                if not self.exists(cr, table) and required:
                    return False

                if not required:
                    continue

                cr.execute(f"SELECT COUNT(*) FROM {table}")
                (count,) = cr.fetchone()
                if self.verbose:
                    utils.info(f"{count} records in {table}")

            return True

    def list_user_keys(self, user_uuid: str | None = None) -> DataList:
        """List all available user keys"""
        with self.cursor() as cr:
            if self.exists(cr, "res_users_key", "version"):
                additional = ", k.version"
            else:
                additional = ", null AS version"

            query = f"""
                SELECT k.uuid, u.login, u.id AS uid, k.fingerprint {additional}
                FROM res_users_key AS k
                LEFT JOIN res_users AS u
                ON u.id = k.user_id
                WHERE k.current = true
            """

            if user_uuid:
                query += " AND k.uuid = %s"

            cr.execute(query, (user_uuid,))
            return list(map(dict, cr.fetchall()))

    def _list_where_clause(self, mapping: dict[str, Any]) -> tuple[str, list | None]:
        clauses, args = [], []
        for key, value in mapping.items():
            if value:
                clauses.append(f"{key} = %s")
                args.append(value)

        if not clauses:
            return "", None
        return f"WHERE {' AND '.join(clauses)}", args

    def _get_uid_from_key_uuid(self, cr: DictCursor, uuid: str | None) -> int | None:
        if not uuid:
            return None

        cr.execute(
            "SELECT user_id FROM res_users_key WHERE uuid = %s",
            [uuid],
        )
        if not cr.rowcount:
            return None

        return cr.fetchone()["user_id"]

    def list_inboxes(self, uuuid: str | None = None, token: str | None = None) -> dict:
        """List all available inboxes"""
        with self.cursor() as cr:
            if not self.exists(cr, "vault_inbox"):
                return {}

            uid = self._get_uid_from_key_uuid(cr, uuuid)
            if not uid:
                return {}

            query = """
                SELECT i.token, i.name, i.accesses, i.expiration,
                    LENGTH(i.secret) > 0 AS secret, LENGTH(i.secret_file) > 0 AS file
                FROM vault_inbox AS i
            """
            where, args = self._list_where_clause({"i.user_id": uid, "i.token": token})
            query += " " + where

            cr.execute(query, args)
            return {i["token"]: dict(i) for i in cr.fetchall()}

    def list_shares(self, uuuid: str | None = None, token: str | None = None) -> dict:
        """List all available shares"""
        with self.cursor() as cr:
            if not self.exists(cr, "vault_share"):
                return {}

            uid = self._get_uid_from_key_uuid(cr, uuuid)
            if not uid:
                return {}

            query = """
                SELECT s.token, s.name, s.accesses, s.expiration,
                    LENGTH(s.secret) > 0 AS secret, LENGTH(s.secret_file) > 0 AS file
                FROM vault_share AS s
            """

            where, args = self._list_where_clause({"s.user_id": uid, "s.token": token})
            query += " " + where

            cr.execute(query, args)
            return {s["token"]: dict(s) for s in cr.fetchall()}

    def list_vaults(self, uuuid: str | None = None, vuuid: str | None = None) -> dict:
        """List all available vaults of the database"""
        with self.cursor() as cr:
            query = """
                SELECT v.uuid, v.name, k.uuid AS user
                FROM res_users_key AS k
                LEFT JOIN res_users AS u ON u.id = k.user_id
                JOIN vault_right AS r ON r.user_id = u.id
                LEFT JOIN vault AS v ON v.id = r.vault_id
            """

            where, args = self._list_where_clause({"k.uuid": uuuid, "v.uuid": vuuid})
            query += " " + where

            cr.execute(query, args)

            data = {}
            for v in cr.fetchall():
                if v["uuid"] not in data:
                    data[v["uuid"]] = {"name": v["name"], "users": set()}
                data[v["uuid"]]["users"].add(v["user"])
            return data

    def getpass(self, password: bool, passfile: bool) -> str:
        passwd = ""
        if password:
            passwd = getpass("Please enter the password: ", stream=sys.stderr)

        if passfile:
            hasher = hashes.Hash(utils.Hash())
            hasher.update(passfile.read())
            passwd += base64.b64encode(hasher.finalize()).decode()

        return passwd

    def extract_private_key(self, key_uuid: str) -> dict[str, Any]:
        """Extract information about the key from the database"""
        with self.cursor() as cr:
            if self.exists(cr, "res_users_key", "version"):
                additional = ", k.version"
            else:
                additional = ", null AS version"

            cr.execute(
                f"""
                    SELECT k.iv, k.fingerprint, k.salt, k.iterations, k.private,
                        u.login {additional}
                    FROM res_users_key AS k
                    LEFT JOIN res_users AS u ON u.id = k.user_id
                    WHERE k.uuid = %s AND k.current = true
                """,
                (key_uuid,),
            )
            return dict(cr.fetchone()) if cr.rowcount else {}

    def _extract_files(self, cr: DictCursor, entry_id: int) -> DataList:
        """Extract all files of the given entry"""
        cr.execute(
            """
                SELECT id, name, iv, value, create_date, write_date
                FROM vault_file WHERE entry_id = %s
            """,
            (entry_id,),
        )
        files: DataList = list(map(dict, cr.fetchall()))
        for file in files:
            file["value"] = bytes(file["value"])
        return files

    def _extract_fields(self, cr: DictCursor, entry_id: int) -> DataList:
        """Extract all fields of the given entry"""
        cr.execute(
            """
                SELECT id, name, iv, value, create_date, write_date
                FROM vault_field WHERE entry_id = %s
            """,
            (entry_id,),
        )
        return list(map(dict, cr.fetchall()))

    def _extract_entries(
        self, cr: DictCursor, vault_id: int, parent_id: int | None = None
    ) -> DataList:
        """Extract all entries of the vault"""
        query = """
            SELECT
                e.id, e.uuid, e.complete_name, e.name,
                e.url, e.note, e.create_date, e.write_date
            FROM vault_entry as e
            LEFT JOIN vault_entry AS p ON e.parent_id = p.id
            WHERE e.vault_id = %s
        """

        if parent_id is None:
            query += " AND e.parent_id IS NULL"
            cr.execute(f"{query} AND e.parent_id IS NULL", (vault_id,))
        else:
            cr.execute(f"{query} AND e.parent_id = %s", (vault_id, parent_id))

        entries: DataList = list(map(dict, cr.fetchall()))
        return [
            {
                **entry,
                "fields": self._extract_fields(cr, entry["id"]),
                "files": self._extract_files(cr, entry["id"]),
                "childs": self._extract_entries(cr, vault_id, entry["id"]),
            }
            for entry in entries
        ]

    def _extract_inbox(self, token: str) -> dict:
        """Extract a specific inbox"""
        with self.cursor() as cr:
            cr.execute(
                """
                    SELECT
                        i.token, i.name, i.secret, i.secret_file, i.filename,
                        i.iv, i.accesses, i.expiration, i.key
                    FROM vault_inbox AS i
                    WHERE i.token = %s
                """,
                (token,),
            )

            if not cr.rowcount:
                return {}

            return dict(cr.fetchone())

    def _extract_rights(self, cr: DictCursor, vault_id: int) -> dict:
        """Extract all rights of the vault"""
        cr.execute(
            """
                SELECT k.uuid, r.key
                FROM res_users_key AS k
                LEFT JOIN res_users AS u ON u.id = k.user_id
                JOIN vault_right AS r ON r.user_id = u.id
                WHERE r.vault_id = %s AND k.current = true
            """,
            (vault_id,),
        )
        return {right["uuid"]: right["key"] for right in cr.fetchall()}

    def _extract_share(self, token: str) -> dict:
        """Extract a specific share"""
        with self.cursor() as cr:
            if self.exists(cr, "vault_share", "iterations"):
                it = "s.iterations"
            else:
                it = "4000 AS iterations"

            cr.execute(
                f"""
                    SELECT
                        s.token, s.name, s.secret, s.secret_file, s.filename,
                        s.salt, s.iv, s.pin, s.accesses, s.expiration, {it}
                    FROM vault_share AS s
                    WHERE s.token = %s
                """,
                (token,),
            )

            if not cr.rowcount:
                return {}

            return dict(cr.fetchone())

    def _extract_vault(self, uuid: str) -> dict:
        """Extract the specific vault"""
        with self.cursor() as cr:
            cr.execute(
                """
                    SELECT id, uuid, name, note, user_id, create_date, write_date
                    FROM vault WHERE uuid = %s
                """,
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

    def extract(
        self,
        user_uuid: str,
        vaults: list[str],
        inboxes: list[str],
        shares: list[str],
        *,
        extract_vault: bool = False,
        extract_inbox: bool = False,
        extract_share: bool = False,
    ) -> dict:
        """Extract data from the database and store it in an exported file"""

        if not extract_vault:
            vaults = []
        elif not vaults:
            vaults = list(self.list_vaults(user_uuid))

        if not extract_inbox:
            inboxes = []
        elif not inboxes:
            inboxes = list(self.list_inboxes(user_uuid))

        if not extract_share:
            shares = []
        elif not shares:
            shares = list(self.list_shares(user_uuid))

        return {
            "type": "exported",
            "uuid": user_uuid,
            "private": self.extract_private_key(user_uuid),
            "inboxes": list(filter(None, map(self._extract_inbox, inboxes))),
            "shares": list(filter(None, map(self._extract_share, shares))),
            "vaults": list(filter(None, map(self._extract_vault, vaults))),
        }

    def _decrypt_entry(self, master_key: str, entry: dict) -> None:
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

    def decrypt_private_key(self, data: dict, password: str) -> utils.PrivateKey | None:
        """Request the password to decrypt the private RSA key"""
        utils.info(f"Using key {data['fingerprint']} for {data['login']}")

        version = data.get("version")
        if self.verbose:
            utils.info(f"Decrypting legacy key with version {version}")

        # Backwards compatibility
        if not version:
            password = f"{data['login']}|{password}"

        key = utils.derive_key(
            password.encode(),
            base64.b64decode(data["salt"]),
            data["iterations"],
        )

        # Decrypt the private key of the user
        private = utils.sym_decrypt(data["iv"], data["private"], key)

        if not private:
            return None

        # Load the private key from the decrypted PEM format
        pem = utils.PEMFormat % base64.b64encode(private)
        return serialization.load_pem_private_key(pem, password=None)

    def _decrypt_master_key(
        self, data: str, private_key: utils.PrivateKey
    ) -> utils.Symmetric:
        """Decrypt the master key for the vault"""
        master_key = private_key.decrypt(base64.b64decode(data), padding=utils.Padding)
        return utils.Symmetric(master_key)

    def decrypt(self, data: dict, password: str) -> dict | None:
        """Decrypt an encrypted file and output it as raw"""
        fields = ["data", "iterations", "iv", "salt"]
        if data.get("type") != "encrypted" or not all(map(data.get, fields)):
            return None

        salt = base64.b64decode(data["salt"].encode())
        iv = base64.b64decode(data["iv"].encode())
        key = utils.derive_key(password.encode(), salt, data["iterations"])

        decrypted = utils.sym_decrypt(iv, data["data"], key, True)
        if not decrypted:
            return None

        return {
            "type": "raw",
            "data": json.loads(decrypted),
        }

    def encrypt(self, data: dict, password: str | None = None) -> dict | None:
        """Encrypt raw data and output it as encrypted data"""
        if data.get("type") != "raw" or not data.get("data"):
            return None

        salt = secrets.token_bytes(utils.SaltLength)
        iv = secrets.token_bytes(utils.IVLength)
        key = utils.derive_key(password.encode(), salt, utils.Iterations)

        content = json.dumps(data["data"], default=utils.serialize)
        encrypted = utils.sym_encrypt(iv, content, key, True)
        return {
            "type": "encrypted",
            "iv": base64.b64encode(iv).decode(),
            "salt": base64.b64encode(salt).decode(),
            "data": encrypted,
            "iterations": utils.Iterations,
        }

    def recover_inbox(self, data: dict, private_key: utils.PrivateKey) -> dict | None:
        """Recover the inbox using the private key on the plain data"""
        iv, key = map(data.pop, ("iv", "key"))

        iv = base64.b64decode(iv.encode())
        key = self._decrypt_master_key(key, private_key)

        secret = data.get("secret")
        if secret:
            data["secret"] = utils.sym_decrypt(iv, secret, key, True)

        secret_file = data.get("secret_file")
        if secret_file:
            data["secret_file"] = utils.sym_decrypt(iv, secret_file, key, True)

        return {"type": "inbox", "data": data}

    def recover_share(self, data: dict, private_key: utils.PrivateKey) -> dict | None:
        """Recover the share using the private key on the plain data"""
        keys = ["iterations", "iv", "pin", "salt"]
        iterations, iv, pin, salt = map(data.pop, keys)

        pin = private_key.decrypt(
            base64.b64decode(pin),
            padding=utils.Padding,
        )[: utils.SharePinSize]

        salt = base64.b64decode(salt.encode())
        iv = base64.b64decode(iv.encode())
        key = utils.derive_key(pin, salt, iterations)

        secret = data.get("secret")
        if secret:
            data["secret"] = utils.sym_decrypt(iv, secret, key, True)

        secret_file = data.get("secret_file")
        if secret_file:
            data["secret_file"] = utils.sym_decrypt(iv, secret_file, key, True)

        return {"type": "share", "data": data}

    def recover_vault(
        self, data: dict, user_uuid: str, private_key: str
    ) -> dict | None:
        """Recover the vault using the private key on plain data"""
        key = data.get("rights", {}).get(user_uuid)
        if not key:
            return None

        data.pop("rights", None)
        master_key = self._decrypt_master_key(key, private_key)
        for entry in data.get("entries", []):
            self._decrypt_entry(master_key, entry)

        return {"type": "plain", "data": data}

    def convert_to_raw(self, data: dict) -> dict | None:
        """Convert the plain decrypted data to an importable format"""
        if data.get("type") == "plain" and data.get("data"):
            return {"type": "raw", "data": data["data"].get("entries", [])}
        return None

    def save_vault_file(self, name: str, content: str, path: str) -> None:
        with open(os.path.join(path, name), "wb+") as fp:
            fp.write(base64.b64decode(content))

    def save_vault_files(self, data: dict, directory: str) -> None:
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
                self.save_vault_file(file["name"], file["value"], path)
