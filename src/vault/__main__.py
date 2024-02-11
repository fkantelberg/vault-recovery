import argparse
import json
import os
from getpass import getpass

from . import utils
from .parser import prepare_parser
from .utils import error, info
from .vault import Vault


def db_params(args: argparse.Namespace) -> dict[str, str | int | None]:
    """Prepate the database parameter from the arguments"""

    if args.db_password:
        db_password = getpass("Please enter the database password: ")
    else:
        db_password = None

    return {
        "dbname": args.db_name,
        "host": args.db_host,
        "user": args.db_user,
        "password": db_password,
        "port": args.db_port,
    }


def main_info(vault: Vault, args: argparse.Namespace) -> None:
    """Return some information about a database"""

    def out_inbox_share(data):
        for token, entry in data.items():
            content = [k for k in ("file", "secret") if entry.get(k)]
            info(f"    {entry['name']} [{token}] [{','.join(content)}]")
            info(f"      Left accesses: {entry['accesses']}")
            info(f"      Expiration: {entry['expiration'].isoformat(' ')}")

    params = db_params(args)
    if not vault.connect(**params):
        error("There is no vault in the current database")
        return

    for user in vault.list_user_keys(args.user):
        info(f"User: {user['login']} [{user['uuid']}] [Version: {user['version']}]")
        info(f"  Fingerprint: {user['fingerprint']}")
        if not args.no_vault:
            info("  Vaults:")
            for uuid, v in vault.list_vaults(user["uuid"], args.vault).items():
                info(f"    {v['name']} [{uuid}]")

        if not args.no_inbox:
            info("  Inboxes:")
            out_inbox_share(vault.list_inboxes(user["uuid"]))

        if not args.no_share:
            info("  Shares:")
            out_inbox_share(vault.list_shares(user["uuid"]))


def main_export(vault: Vault, args: argparse.Namespace) -> dict | None:
    """Export from a database"""

    params = db_params(args)
    if not vault.connect(**params):
        error("There is no vault in the current database")
        return None

    if not args.user:
        error("Missing user")
        return None

    return vault.extract(
        args.user,
        args.vault,
        args.inbox,
        args.share,
        extract_inbox=not args.no_inbox,
        extract_share=not args.no_share,
        extract_vault=not args.no_vault,
    )


def main_encrypt(vault: Vault, args: argparse.Namespace) -> None:
    """Encrypt a raw file"""

    content = json.load(args.input)

    password = vault.getpass(args.password, args.passfile)
    encrypted = vault.encrypt(content, password)
    if not encrypted:
        error("Encryption failed")
        return

    utils.output(encrypted)


def main_decrypt(vault: Vault, args: argparse.Namespace) -> None:
    """Decrypt an encrypted file"""

    content = json.load(args.input)

    password = vault.getpass(args.password, args.passfile)
    raw = vault.decrypt(content, password)

    if args.output and raw:
        os.makedirs(args.output, exist_ok=True)
        vault.save_vault_files(raw, args.output)

        utils.dump_json(os.path.join(args.output, "raw.json"), raw)
    else:
        utils.output(raw)


def main_recover(vault: Vault, args: argparse.Namespace) -> None:
    """Recover the secrets from a file or database"""

    if not args.password and not args.passfile:
        error("Neither password nor passfile given")
        return

    if args.input:
        info("Loading from input")
        content = json.load(args.input)
    else:
        info("Loading from database")
        content = main_export(vault, args)

    if not content or content.get("type") != "exported":
        error("Nothing to recover")
        return

    info("Decrypting private key.")
    password = vault.getpass(args.password, args.passfile)
    private_key = vault.decrypt_private_key(content["private"], password=password)
    if not private_key:
        error("Private key is not decryptable")
        return

    if args.encrypt_password or args.encrypt_passfile:
        info("Building encryption key")
        encrypt_password = vault.getpass(args.encrypt_password, args.encrypt_passfile)
    else:
        encrypt_password = None

    if not args.no_inbox:
        main_recover_inboxes(
            vault,
            content,
            private_key=private_key,
            args=args,
        )

    if not args.no_share:
        main_recover_shares(
            vault,
            content,
            private_key=private_key,
            args=args,
        )

    if not args.no_vault:
        main_recover_vaults(
            vault,
            content,
            private_key=private_key,
            encrypt_password=encrypt_password,
            args=args,
        )


def main_recover_inboxes(
    vault: Vault,
    content: dict,
    private_key: utils.PrivateKey,
    args: argparse.Namespace,
) -> None:
    path = os.path.join(args.output, "inbox")

    for data in content.get("inboxes", []):
        token = data.get("token")
        if not token:
            continue

        info(f"Recovering inbox {data['name']} [{token}]")
        plain = vault.recover_inbox(data, private_key)
        if not plain:
            error(f"Inbox {token} not decryptable")
            continue

        inbox_path = os.path.join(path, token)
        os.makedirs(inbox_path, exist_ok=True)
        utils.dump_json(os.path.join(inbox_path, "plain.json"), plain)

        inbox: dict = plain.get("data", {})
        if args.files and all(map(inbox.get, ("filename", "secret_file"))):
            vault.save_vault_file(inbox["filename"], inbox["secret_file"], inbox_path)


def main_recover_shares(
    vault: Vault,
    content: dict,
    private_key: utils.PrivateKey,
    args: argparse.Namespace,
) -> None:
    path = os.path.join(args.output, "share")

    for data in content.get("shares", []):
        token = data.get("token")
        if not token:
            continue

        info(f"Recovering share {data['name']} [{token}]")
        plain = vault.recover_share(data, private_key)
        if not plain:
            error(f"Share {token} not decryptable")
            continue

        share_path = os.path.join(path, token)
        os.makedirs(share_path, exist_ok=True)
        utils.dump_json(os.path.join(share_path, "plain.json"), plain)

        share: dict = plain.get("data", {})
        if args.files and all(map(share.get, ("filename", "secret_file"))):
            vault.save_vault_file(share["filename"], share["secret_file"], share_path)


def main_recover_vaults(
    vault: Vault,
    content: dict,
    private_key: utils.PrivateKey,
    encrypt_password: str | None,
    args: argparse.Namespace,
) -> None:
    path = os.path.join(args.output, "vault")

    for data in content.get("vaults", []):
        vuuid = data.get("uuid")
        if not vuuid:
            continue

        info(f"Recovering vault {vuuid}")
        plain = vault.recover_vault(data, content["uuid"], private_key)
        if not plain:
            error(f"Vault {vuuid} not decryptable")
            continue

        raw = vault.convert_to_raw(plain)
        sub_path = os.path.join(path, vuuid)
        os.makedirs(sub_path, exist_ok=True)
        if args.files and plain:
            vault.save_vault_files(plain, sub_path)

        if args.plain and plain:
            utils.dump_json(os.path.join(sub_path, "plain.json"), plain)

        if args.raw and raw:
            utils.dump_json(os.path.join(sub_path, "raw.json"), raw)

        if raw and encrypt_password:
            encrypted = vault.encrypt(raw, password=encrypt_password)
            utils.dump_json(os.path.join(sub_path, "encrypted.json"), encrypted)


def main(arg_list: list[str] | None = None) -> None:
    parser = prepare_parser()

    args = parser.parse_args(arg_list)

    vault = Vault(verbose=args.verbose)
    if args.mode == "info":
        main_info(vault, args)
    elif args.mode == "export":
        content = main_export(vault, args)
        utils.output(content)
    elif args.mode == "recover":
        main_recover(vault, args)
    elif args.mode == "decrypt":
        main_decrypt(vault, args)
    elif args.mode == "encrypt":
        main_encrypt(vault, args)
    else:
        error(f"Invalid mode {args.mode}")


if __name__ == "__main__":
    main()
