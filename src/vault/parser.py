import argparse

from .utils import file_type
from .vault import Tables


def parser_add_database(parser: argparse.ArgumentParser) -> None:
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


def parser_add_selection(
    parser: argparse.ArgumentParser, require_user: bool = False
) -> None:
    parser.add_argument(
        "--inbox",
        default=[],
        action="append",
        help="Specify a inbox's token to process only these specific one. This "
        "option can be specified multiple times to select multiple inboxes",
    )
    parser.add_argument(
        "--share",
        default=[],
        action="append",
        help="Specify a share's token to process only these specific one. This "
        "option can be specified multiple times to select multiple shares",
    )
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
    parser.add_argument(
        "--no-inbox",
        action="store_true",
        help="Skip inboxes",
    )
    parser.add_argument(
        "--no-share",
        action="store_true",
        help="Skip shares",
    )
    parser.add_argument(
        "--no-vault",
        action="store_true",
        help="Skip vaults",
    )


def prepare_export_parser(parser: argparse._SubParsersAction) -> None:
    subparser = parser.add_parser(
        "export",
        help="Export vaults from the database but doesn't decrypt them. This is "
        "useful to move the data to another machine to decrypt it in a secure "
        "environment.",
    )
    parser_add_database(subparser)
    parser_add_selection(subparser, True)


def prepare_info_parser(parser: argparse._SubParsersAction) -> None:
    subparser = parser.add_parser("info", help="Gather information from the database")
    parser_add_database(subparser)
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
    subparser.add_argument(
        "--no-inbox",
        action="store_true",
        help="Skip inboxes",
    )
    subparser.add_argument(
        "--no-share",
        action="store_true",
        help="Skip shares",
    )
    subparser.add_argument(
        "--no-vault",
        action="store_true",
        help="Skip vaults",
    )


def prepare_decrypt_parser(parser: argparse._SubParsersAction) -> None:
    subparser = parser.add_parser(
        "decrypt",
        help="Decrypt an encrypted file exported from a vault",
    )
    parser_add_database(subparser)
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


def prepare_encrypt_parser(parser: argparse._SubParsersAction) -> None:
    subparser = parser.add_parser(
        "encrypt",
        help="Encrypt a raw file exported from a vault",
    )
    parser_add_database(subparser)
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


def prepare_recover_parser(parser: argparse._SubParsersAction) -> None:
    subparser = parser.add_parser(
        "recover",
        help="Recover vaults from a previously exported file or using the database. "
        "The recovery stores the vaults inside of the output directory in json file "
        "importable by the vault module as raw or encrypted version. Files inside of "
        "the vaults are additionally placed in subdirectories.",
    )
    parser_add_database(subparser)
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


def prepare_parser() -> argparse.ArgumentParser:
    names = list(Tables)
    tables = ", ".join(map(repr, names[:-1])) + f" and {repr(names[-1])}"

    parser = argparse.ArgumentParser(
        description="%(prog)s provides utilities for a disaster recovery for the Odoo "
        "vault module from backups. Do not run the decryption on the server because "
        f"it will compromise the module's concept. Only the database tables {tables} "
        "are required for a recovery."
    )

    parser.add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true",
    )

    sub = parser.add_subparsers(dest="mode", required=True)
    prepare_info_parser(sub)
    prepare_export_parser(sub)
    prepare_decrypt_parser(sub)
    prepare_encrypt_parser(sub)
    prepare_recover_parser(sub)

    return parser
