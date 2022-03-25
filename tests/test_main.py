import json
import os
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import MagicMock, patch

import pytest

from vault import Vault
from vault import __main__ as main
from vault import utils

from . import example


@pytest.fixture
def vault():
    return Vault(verbose=True)


@pytest.fixture
def exported():
    return {
        "type": "exported",
        "uuid": "60341751-62c2-4a2d-ae54-c5734e90bf47",
        "private": example.PrivateKey,
        "vaults": [example.Exported],
    }


@pytest.fixture
def recover_args():
    return MagicMock(
        password=False,
        passfile=False,
        input=None,
        encrypt_password=False,
        encrypt_passfile=None,
    )


def test_info(vault):
    user = {"login": "admin", "uuid": "a-b-c", "fingerprint": "ab:cd"}
    v = {"name": "vault"}
    vault.connect = MagicMock(return_value=False)
    vault.list_user_keys = MagicMock(return_value=[user])
    vault.list_vaults = MagicMock(return_value={"v-a-u-l-t": v})
    args = MagicMock(user="a-b-c", vault="v-a-u-l-t")

    main.main_info(vault, args, {"abc": 42})
    vault.connect.assert_called_once_with(abc=42)
    vault.list_user_keys.assert_not_called()
    vault.list_vaults.assert_not_called()

    vault.connect.return_value = True
    main.main_info(vault, args, {"abc": 42})
    vault.list_user_keys.assert_called_once_with("a-b-c")
    vault.list_vaults.assert_called_once_with("a-b-c", args.vault)


def test_export(vault):
    vault.connect = MagicMock(return_value=False)
    vault.extract = MagicMock()
    args = MagicMock(user=False, vault="v-a-u-l-t")

    main.main_export(vault, args, {"abc": 42})
    vault.connect.assert_called_once_with(abc=42)
    vault.extract.assert_not_called()

    vault.connect.return_value = True
    main.main_export(vault, args, {"abc": 42})
    vault.extract.assert_not_called()

    args.user = "a-b-c"
    main.main_export(vault, args, {"abc": 42})
    vault.extract.assert_called_once_with(args.user, args.vault)


def test_encrypt(vault):
    vault.encrypt = MagicMock(return_value=None)
    vault.getpass = MagicMock()
    file = MagicMock()
    file.read.return_value = '{"abc": 42}'
    args = MagicMock(input=file)

    main.main_encrypt(vault, args)
    vault.encrypt.return_value = True
    main.main_encrypt(vault, args)


def test_decrypt(vault):
    vault.decrypt = MagicMock(return_value=None)
    vault.getpass = MagicMock()
    vault.save_vault_files = MagicMock()
    file = MagicMock()
    file.read.return_value = '{"abc": 42}'
    args = MagicMock(input=file, output=False)

    main.main_decrypt(vault, args)
    vault.decrypt.return_value = True
    main.main_decrypt(vault, args)
    vault.save_vault_files.assert_not_called()

    with TemporaryDirectory() as d:
        args.output = d
        main.main_decrypt(vault, args)
        vault.save_vault_files.assert_called_once()


def test_recover_full(vault, exported, recover_args):
    vault.connect = MagicMock(return_value=False)
    vault.getpass = MagicMock(return_value="test")
    vault.extract = MagicMock(return_value={"type": "invalid"})

    with NamedTemporaryFile("w+") as fp, TemporaryDirectory() as d:
        recover_args.output = d

        fp.write(json.dumps(exported, default=utils.serialize))
        fp.flush()
        fp.seek(0)

        main.main_recover(vault, recover_args, {})

        vault.getpass.assert_not_called()
        recover_args.password = True
        main.main_recover(vault, recover_args, {})

        recover_args.input = fp
        main.main_recover(vault, recover_args, {})

        v = os.path.join(d, "a8309ac1-07ac-4704-8f86-6499a5fc0777")
        assert os.path.isdir(v)
        assert os.path.isfile(os.path.join(v, "raw.json"))
        assert os.path.isfile(os.path.join(v, "plain.json"))
        assert not os.path.isfile(os.path.join(v, "encrypted.json"))
        assert os.path.isfile(
            os.path.join(v, "4d1bfb58-765f-423c-ada0-b612f791e4f7", "test.txt")
        )

        fp.seek(0)
        recover_args.encrypt_password = True
        main.main_recover(vault, recover_args, {})
        assert os.path.isfile(os.path.join(v, "encrypted.json"))


def test_recover_export_flags(vault, exported, recover_args):
    vault.connect = MagicMock(return_value=False)
    vault.getpass = MagicMock(return_value="test")
    vault.extract = MagicMock(return_value={"type": "invalid"})

    recover_args.plain = False
    recover_args.raw = False
    recover_args.files = False
    recover_args.password = True

    with NamedTemporaryFile("w+") as fp, TemporaryDirectory() as d:
        v = os.path.join(d, "a8309ac1-07ac-4704-8f86-6499a5fc0777")
        recover_args.input = fp
        recover_args.output = d
        fp.write(json.dumps(exported, default=utils.serialize))
        fp.flush()

        fp.seek(0)
        main.main_recover(vault, recover_args, {})
        assert not os.path.isfile(os.path.join(v, "raw.json"))
        assert not os.path.isfile(os.path.join(v, "plain.json"))
        assert not os.path.isfile(
            os.path.join(v, "4d1bfb58-765f-423c-ada0-b612f791e4f7", "test.txt")
        )

        recover_args.plain = True
        fp.seek(0)
        main.main_recover(vault, recover_args, {})
        assert os.path.isfile(os.path.join(v, "plain.json"))
        assert not os.path.isfile(os.path.join(v, "raw.json"))
        assert not os.path.isfile(
            os.path.join(v, "4d1bfb58-765f-423c-ada0-b612f791e4f7", "test.txt")
        )

        recover_args.raw = True
        fp.seek(0)
        main.main_recover(vault, recover_args, {})
        assert os.path.isfile(os.path.join(v, "plain.json"))
        assert os.path.isfile(os.path.join(v, "raw.json"))
        assert not os.path.isfile(
            os.path.join(v, "4d1bfb58-765f-423c-ada0-b612f791e4f7", "test.txt")
        )

        recover_args.files = True
        fp.seek(0)
        main.main_recover(vault, recover_args, {})
        assert os.path.isfile(os.path.join(v, "plain.json"))
        assert os.path.isfile(os.path.join(v, "raw.json"))
        assert os.path.isfile(
            os.path.join(v, "4d1bfb58-765f-423c-ada0-b612f791e4f7", "test.txt")
        )


def test_recover_invalid(vault, exported, recover_args):
    vault.connect = MagicMock(return_value=False)
    vault.getpass = MagicMock(return_value="test")
    vault.extract = MagicMock(return_value={"type": "invalid"})
    vault.recover = MagicMock(return_value=False)
    with NamedTemporaryFile("w+") as fp, TemporaryDirectory() as d:
        recover_args.output = d
        fp.write(json.dumps(exported, default=utils.serialize))
        fp.flush()
        fp.seek(0)
        recover_args.input = fp
        main.main_recover(vault, recover_args, {})
        assert os.listdir(d) == []


def test_recover_no_vault(vault, exported, recover_args):
    vault.connect = MagicMock(return_value=False)
    vault.getpass = MagicMock(return_value="test")
    vault.extract = MagicMock(return_value={"type": "invalid"})
    exported = dict(exported, vaults=[{}])
    with NamedTemporaryFile("w+") as fp, TemporaryDirectory() as d:
        recover_args.output = d
        fp.write(json.dumps(exported, default=utils.serialize))
        fp.flush()
        fp.seek(0)
        recover_args.input = fp
        main.main_recover(vault, recover_args, {})
        assert os.listdir(d) == []


def test_main():
    with patch("vault.__main__.main_info") as mock:
        main.main(("info", "-d", "odoo"))
        mock.assert_called_once()

    with patch("vault.__main__.main_export") as mock:
        main.main(("export", "--user", "a-b-c"))
        mock.assert_called_once()

    with patch("vault.__main__.main_recover") as mock:
        main.main(("recover", "-i", "-", "--output", "/tmp/"))
        mock.assert_called_once()

    with patch("vault.__main__.main_encrypt") as mock:
        main.main(("encrypt", "-i", "-"))
        mock.assert_called_once()

    with patch("vault.__main__.main_decrypt") as mock:
        main.main(("decrypt", "-i", "-"))
        mock.assert_called_once()

    with patch("sys.exit") as mock, patch("vault.__main__.parse_args") as m:
        m.return_value.db_password = False
        main.main(("invalid",))
        mock.assert_called_once()

    with patch("vault.__main__.getpass") as mock:
        main.main(("info", "-w"))
        mock.assert_called_once()
