import argparse
import json
import os
import sys
from getpass import getpass

from .utils import error, file_type, info, output, serialize
from .vault import Tables, Vault


def parser_add_basics(parser):
    parser.add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-d",
        "--database",
        dest="db_name",
        default=None,
        help="Name of the database",
    )
    parser.add_argument(
        "-H",
        "--db-host",
        default=None,
        help="Host of the database",
    )
    parser.add_argument(
        "-U",
        "--db-user",
        default=None,
        help="User of the database",
    )
    parser.add_argument(
        "-p",
        "--db-port",
        default=5432,
        help="Port of the database",
    )
    parser.add_argument(
        "-w",
        "--db-password",
        default=False,
        action="store_true",
        help="Activates the password authentication instead of peer authentication",
    )


def parser_add_selection(parser, require_user=False):
    parser.add_argument(
        "--user",
        default=None,
        required=require_user,
        help="Specify the user's UUID to use for the recovery",
    )
    parser.add_argument(
        "--vault",
        default=[],
        action="append",
        help="Specify a vault's UUID to process only these specific one. This "
        "option can be specified multiple times to select multiple vaults",
    )


def parse_args(args=None):
    tables = ", ".join(map(repr, Tables[:-1])) + f" and {repr(Tables[-1])}"

    parser = argparse.ArgumentParser(
        description="%(prog)s provides utilities for a disaster recovery for the Odoo "
        "vault module from backups. Do not run the decryption on the server because "
        f"it will compromise the module's concept. Only the database tables {tables} "
        "are required for a recovery."
    )

    sub = parser.add_subparsers(dest="mode")
    subparser = sub.add_parser("info", help="Gather information from the database")
    parser_add_basics(subparser)
    subparser.add_argument(
        "--user",
        default=None,
        help="Specify an user's UUID to gather more specific information",
    )
    subparser.add_argument(
        "--vault",
        default=None,
        help="Specify a vault's UUID to gather more specific information",
    )

    subparser = sub.add_parser(
        "export",
        help="Export vaults from the database but doesn't decrypt them. This is "
        "useful to move the data to another machine to decrypt it in a secure "
        "environment.",
    )
    parser_add_basics(subparser)
    parser_add_selection(subparser, True)

    subparser = sub.add_parser(
        "decrypt",
        help="Decrypt an encrypted file exported from a vault",
    )
    parser_add_basics(subparser)
    subparser.add_argument(
        "-i",
        "--input",
        default=None,
        type=file_type(),
        required=True,
        help="The previously exported encrypted file",
    )
    subparser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Directory to store the decrypted informations",
    )
    subparser.add_argument(
        "--password",
        default=False,
        action="store_true",
        help="Specify the password to decrypt the exported file",
    )
    subparser.add_argument(
        "--passfile",
        default=None,
        type=argparse.FileType("rb"),
        help="Specify the passfile to decrypt the exported file",
    )

    subparser = sub.add_parser(
        "encrypt",
        help="Encrypt a raw file exported from a vault",
    )
    parser_add_basics(subparser)
    subparser.add_argument(
        "-i",
        "--input",
        default=None,
        type=file_type(),
        required=True,
        help="The previously exported raw file",
    )
    subparser.add_argument(
        "--password",
        default=False,
        action="store_true",
        help="Specify the password to decrypt the exported file",
    )
    subparser.add_argument(
        "--passfile",
        default=None,
        type=argparse.FileType("rb"),
        help="Specify the passfile to decrypt the exported file",
    )

    subparser = sub.add_parser(
        "recover",
        help="Recover vaults from a previously exported file or using the database. "
        "The recovery stores the vaults inside of the output directory in json file "
        "importable by the vault module as raw or encrypted version. Files inside of "
        "the vaults are additionally placed in subdirectories.",
    )
    parser_add_basics(subparser)
    parser_add_selection(subparser)
    subparser.add_argument(
        "-i",
        "--input",
        default=None,
        type=file_type(),
        help="Load from a file instead of a database",
    )
    subparser.add_argument(
        "-o",
        "--output",
        default=None,
        required=True,
        help="Directory to store the recovered informations",
    )
    subparser.add_argument(
        "--password",
        default=False,
        action="store_true",
        help="Specify the password to decrypt the user's private key",
    )
    subparser.add_argument(
        "--passfile",
        default=None,
        type=argparse.FileType("rb"),
        help="Specify the passfile to decrypt the user's private key",
    )
    subparser.add_argument(
        "--no-plain",
        dest="plain",
        default=True,
        action="store_false",
        help="Don't write a `plain.json` file",
    )
    subparser.add_argument(
        "--no-raw",
        dest="raw",
        default=True,
        action="store_false",
        help="Don't write a `raw.json` file",
    )
    subparser.add_argument(
        "--no-files",
        dest="files",
        default=True,
        action="store_false",
        help="Don't write the files into subdirectories",
    )
    subparser.add_argument(
        "--encrypt-password",
        default=False,
        action="store_true",
        help="Specify the password to encrypt the recovered vault. This will create "
        "a `encrypted.json` file",
    )
    subparser.add_argument(
        "--encrypt-passfile",
        default=None,
        type=file_type("rb"),
        help="Specify the passfile to encrypt the recovered vault. This will create "
        "a `encrypted.json` file",
    )

    return parser.parse_args(args)


def main_info(vault, args, db_params):
    if not vault.connect(**db_params):
        error("There is no vault in the current database")
        return

    for user in vault.list_user_keys(args.user):
        info(f"User: {user['login']} [{user['uuid']}]")
        info(f"  Fingerprint: {user['fingerprint']}")
        info("  Vaults:")
        for uuid, v in vault.list_vaults(user["uuid"], args.vault).items():
            info(f"    {v['name']} [{uuid}]")


def main_export(vault, args, db_params):
    if not vault.connect(**db_params):
        error("There is no vault in the current database")
        return

    if not args.user:
        error("Missing user")
        return

    return vault.extract(args.user, args.vault)


def main_encrypt(vault, args):
    content = json.load(args.input)

    password = vault.getpass(args.password, args.passfile)
    encrypted = vault.encrypt(content, password)
    if not encrypted:
        error("Encryption failed")
        return

    output(encrypted)


def main_decrypt(vault, args):
    content = json.load(args.input)

    password = vault.getpass(args.password, args.passfile)
    raw = vault.decrypt(content, password)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        vault.save_vault_files(raw, args.output)

        with open(os.path.join(args.output, "raw.json"), "w+") as fp:
            json.dump(raw, fp, sort_keys=True, indent=2, default=serialize)
    else:
        output(raw)


def main_recover(vault, args, db_params):
    if not args.password and not args.passfile:
        error("Neither password nor passfile given")
        return

    if args.input:
        content = json.load(args.input)
    else:
        content = main_export(vault, args, db_params)

    if not content or content.get("type") != "exported":
        return

    info("Decrypting private key.")
    password = vault.getpass(args.password, args.passfile)
    private_key = vault.decrypt_private_key(content["private"], password=password)

    if args.encrypt_password or args.encrypt_passfile:
        info("Building encryption key")
        encrypt_password = vault.getpass(args.encrypt_password, args.encrypt_passfile)
    else:
        encrypt_password = None

    for data in content.get("vaults", []):
        vuuid = data.get("uuid")
        info(f"Recovering {vuuid}")
        if not vuuid:
            continue

        plain = vault.recover(data, content["uuid"], private_key)
        if not plain:
            error(f"Vault {vuuid} not decryptable")
            continue

        raw = vault.convert_to_raw(plain)
        path = os.path.join(args.output, vuuid)
        os.makedirs(path, exist_ok=True)
        if args.files:
            vault.save_vault_files(plain, path)

        if args.plain:
            with open(os.path.join(path, "plain.json"), "w+") as fp:
                json.dump(plain, fp, sort_keys=True, indent=2, default=serialize)

        if args.raw:
            with open(os.path.join(path, "raw.json"), "w+") as fp:
                json.dump(raw, fp, sort_keys=True, indent=2, default=serialize)

        if encrypt_password:
            encrypted = vault.encrypt(raw, password=encrypt_password)

            with open(os.path.join(path, "encrypted.json"), "w+") as fp:
                json.dump(encrypted, fp, sort_keys=True, indent=2, default=serialize)


def main(args=None):
    args = parse_args(args)

    if args.db_password:
        db_password = getpass("Please enter the database password: ")
    else:
        db_password = None

    db_params = {
        "dbname": args.db_name,
        "host": args.db_host,
        "user": args.db_user,
        "password": db_password,
        "port": args.db_port,
    }

    vault = Vault(verbose=args.verbose)
    if args.mode == "info":
        main_info(vault, args, db_params)
    elif args.mode == "export":
        content = main_export(vault, args, db_params)
        output(content)
    elif args.mode == "recover":
        main_recover(vault, args, db_params)
    elif args.mode == "decrypt":
        main_decrypt(vault, args)
    elif args.mode == "encrypt":
        main_encrypt(vault, args)
    else:
        error(f"Invalid mode {args.mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
