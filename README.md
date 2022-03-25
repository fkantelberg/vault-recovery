[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/vault-recovery)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# vault-recovery

This tool provides utilities for a disaster recovery for the Odoo vault module from
database backups or formerly exported files. The backups need atleast the following
tables for the recovery:

- res_users
- res_users_key
- vault
- vault_entry
- vault_field
- vault_file
- vault_right

## Installation

```bash
$ pip3 install vault-recovery
```

## Security

Do not run the `recover` or `decrypt` mode on the server. This will compromise the
security design of the vault module.

## Usage

The tool supports different operation modes for specific purposes.

`vault info [...]` can be used to retrieve information from a postgres database about
available vaults. It can be used to get UUIDs of users and vaults with some additional
information. The UUIDs are used in other modes.

```bash
$ vault info -d odoo
User: admin [6cf47287-d791-44a0-b073-78659959ca3f]
  Fingerprint: 61:a7:70:73:75:06:61:ad:fc:0e:9a:3c:bd:99:a0:17:be:7f:35:5e:31:d0:80:e4:fd:cc:90:ac:be:5b:e8:82
  Vaults:
    Test Vault [cee24057-4318-46b8-b227-05ec687df64e]
```

`vault export [...]` can be used to export vaults from a database into `exported` files.
These files include everything from the database which is needed to recover the database
including the encrypted master key, private key, and entries.

```bash
$ vault export -d odoo --user 6cf47287-d791-44a0-b073-78659959ca3f > vaults.json
```

`vault recover [...]` can be used to recover the secrets from a vault. It can recover
from a database or from a previously exported `exported` file as the following example
shows. The data is put inside of the output directory as `raw`, `plain`, and
`encrypted` files.

```bash
$ vault recover -d odoo -i vaults.json --password --output ~/vaults
```

`vault encrypt [...]` can be used to protect `raw` files with password or passfiles.

```bash
$ vault encrypt -i raw.json --password > encrypted.json
```

`vault decrypt [...]` can be used to decrypt `encrypted` files.

```bash
$ vault decrypt -i encrypted.json --password -o ~/vaults > raw.json
```

## Files types

The tool outputs various JSON files for different purposes to store the data and to
allow splitting the process into steps. All files are structured as a dictionary
with a `type` key. The following types exists:

- `exported`: contains all information needed to recover vaults. They can be used
to recover the data on more secure environments.

- `plain`: contains the most information of a recovered vault. These files are
unencrypted.

- `raw`: contains unencrypted entries ready to be imported into a running vault

- `encrypted`: contains encrypted entries ready to be imported into a running vault
