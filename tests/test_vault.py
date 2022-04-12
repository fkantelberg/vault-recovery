import os
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import pytest
from psycopg2.errors import UndefinedTable

from vault import Vault, utils

from . import example


@pytest.fixture
def vault():
    return Vault(verbose=True)


@patch("vault.vault.connect")
def test_connect(connect_mock, vault):
    vault.check_database = MagicMock()
    vault.connect(database="testdb")

    connect_mock.assert_called_once_with(database="testdb")
    vault.check_database.assert_called_once()

    vault.conn = MagicMock()
    with vault.cursor() as cr:
        assert cr == vault.conn.cursor.return_value.__enter__.return_value


def test_check_database(vault):
    mock = vault.cursor = MagicMock()
    cursor = mock.return_value.__enter__.return_value
    cursor.fetchone.return_value = (1,)

    assert vault.check_database()

    cursor.execute.side_effect = UndefinedTable
    assert not vault.check_database()


def test_list(vault):
    mock = vault.cursor = MagicMock()
    cursor = mock.return_value.__enter__.return_value
    cursor.fetchall.return_value = [{1: 42}]

    assert vault.list_user_keys("a-b-c") == [{1: 42}]

    with pytest.raises(KeyError):
        vault.list_vaults()

    cursor.fetchall.return_value = [{"uuid": "1-1-1", "name": "abc", "user": "def"}]
    vault.list_vaults("1-1-1", "a-b-c")
    vault.list_vaults("1-1-1")
    vault.list_vaults(vuuid="1-1-1")


@patch("vault.vault.getpass")
def test_getpass(getpass_mock, vault):
    getpass_mock.return_value = "abc"
    passfile = MagicMock()
    passfile.read.return_value = b"def"

    assert vault.getpass(True, None) == "abc"
    getpass_mock.assert_called_once()
    passfile.read.assert_not_called()

    getpass_mock.reset_mock()
    assert len(vault.getpass(False, passfile)) > utils.Hash.digest_size
    getpass_mock.assert_not_called()
    passfile.read.assert_called_once()


def test_conversion(vault):
    assert vault.convert_to_raw(example.Plain) == example.Raw

    private_key = vault.decrypt_private_key(example.PrivateKey, password="test")
    recovered = vault.recover(
        example.Exported,
        "60341751-62c2-4a2d-ae54-c5734e90bf47",
        private_key,
    )
    assert recovered == example.Plain

    encrypted = vault.encrypt(example.Raw, "test")
    assert encrypted["type"] == "encrypted"
    decrypted = vault.decrypt(encrypted, "test")
    assert decrypted == example.Raw

    assert vault.encrypt(encrypted, "test") is None
    assert vault.decrypt(example.Raw, "test") is None
    assert vault.recover(example.Exported, "test", private_key) is None
    assert vault.convert_to_raw(example.Raw) is None


def test_save_to_files(vault):
    with TemporaryDirectory() as d:
        vault.save_vault_files(example.Plain, d)

        filename = os.path.join(d, "4d1bfb58-765f-423c-ada0-b612f791e4f7", "test.txt")
        with open(filename) as fp:
            assert fp.read() == "hello world\n"

    with TemporaryDirectory() as d:
        vault.save_vault_files(example.Raw, d)

        filename = os.path.join(d, "4d1bfb58-765f-423c-ada0-b612f791e4f7", "test.txt")
        with open(filename) as fp:
            assert fp.read() == "hello world\n"

    with TemporaryDirectory() as d:
        vault.save_vault_files(example.Exported, d)
        assert os.listdir(d) == []


def test_private_key_extraction(vault):
    mock = vault.cursor = MagicMock()
    vault.exists = MagicMock()
    cursor = mock.return_value.__enter__.return_value
    cursor.fetchone.return_value = {1: 42}

    assert vault.extract_private_key("abc") == {1: 42}
    cursor.execute.assert_called_once()
    cursor.fetchone.assert_called_once()
    vault.exists.assert_called_once()

    cursor.rowcount = 0
    assert vault.extract_private_key("abc") == {}


def test_file_extraction(vault):
    cursor = MagicMock()
    cursor.fetchall.return_value = [{"value": [42]}, {"value": b"abc"}]
    assert vault._extract_files(cursor, "key") == [{"value": b"*"}, {"value": b"abc"}]


def test_field_extraction(vault):
    cursor = MagicMock()
    cursor.fetchall.return_value = [{"value": [42]}, {"value": b"abc"}]
    assert vault._extract_fields(cursor, "key") == [{"value": [42]}, {"value": b"abc"}]


def test_entry_extraction(vault):
    cursor = MagicMock()
    cursor.fetchall.return_value = [{"id": 42}]
    vault._extract_fields = MagicMock()
    vault._extract_files = MagicMock()

    orig = vault._extract_entries
    vault._extract_entries = MagicMock()

    extracted = orig(cursor, "vault")
    assert all(x in extracted[0] for x in ["id", "childs", "fields", "files"])
    vault._extract_fields.assert_called_once_with(cursor, 42)
    vault._extract_files.assert_called_once_with(cursor, 42)
    vault._extract_entries.assert_called_once_with(cursor, "vault", 42)

    extracted = orig(cursor, "vault", 42)
    assert all(x in extracted[0] for x in ["id", "childs", "fields", "files"])


def test_right_extraction(vault):
    cursor = MagicMock()
    right = {"a-b-c": "key"}
    cursor.fetchall.return_value = [{"uuid": k, "key": v} for k, v in right.items()]

    assert vault._extract_rights(cursor, "vault") == right


def test_vault_extraction(vault):
    vault._extract_entries = MagicMock()
    vault._extract_rights = MagicMock()

    mock = vault.cursor = MagicMock()
    cursor = mock.return_value.__enter__.return_value
    cursor.fetchone.return_value = {"id": 42}
    cursor.rowcount = 0

    assert vault._extract_vault("a-b-c") == {}

    cursor.rowcount = 1
    extracted = vault._extract_vault("a-b-c")
    assert all(x in extracted for x in ["id", "entries", "rights"])
    vault._extract_entries.assert_called_once_with(cursor, 42)
    vault._extract_rights.assert_called_once_with(cursor, 42)


def test_extraction(vault):
    vault._extract_vault = MagicMock()
    vault.extract_private_key = MagicMock()
    vault.list_vaults = MagicMock()

    extracted = vault.extract("user")
    assert all(x in extracted for x in ["type", "vaults", "private", "uuid"])
    vault.extract_private_key.assert_called_once_with("user")
    vault.list_vaults.assert_called_once_with("user")
