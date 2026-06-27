# VaultKeeper

A local, encrypted command-line password manager written in Python. No cloud sync, no telemetry — your vault lives in a single SQLite file on your own machine, protected by one master password.

## Features

- **Master password authentication** — one password unlocks everything. The master password itself is never stored; only the means to verify it.
- **Strong encryption at rest** — every saved password (and TOTP secret) is encrypted with Fernet (AES-128-CBC + HMAC) before it ever touches disk.
- **Brute-force throttling** — repeated failed login attempts trigger an increasing lockout period.
- **Full CRUD** — add, get, list, search, update, and delete credential entries.
- **Tags/categories** — organize entries with a single tag each (e.g. `work`, `banking`, `personal`); filter with `list --tag` or browse all tags with `tags`.
- **2FA / TOTP codes** — store a TOTP secret per entry and generate live 6-digit codes on demand via `get`.
- **Password rotation** — `regen` lets you either paste in a password you already changed on the website, or generate a new one and print it clearly so you can update the site.
- **Security audit** — `audit` scans your whole vault for reused passwords and weak ones, without ever printing the actual reused password.
- **Stale password reminders** — `list --stale-days N` flags entries that haven't been updated recently.
- **Bulk CSV import/export** — bring in existing passwords from a spreadsheet/CSV export from another tool, or export your vault to CSV.
- **Secure password generator** — configurable length and character sets, built on Python's `secrets` module.
- **Password strength checker** — entropy-based scoring with specific, actionable feedback.
- **Clipboard integration** — `get` copies the password to your clipboard and clears it automatically after 15 seconds.
- **Encrypted backups** — export your vault to a portable, passphrase-protected file, and import it back later.

## How the encryption works

```
Master Password ──► PBKDF2HMAC-SHA256 (260,000 iterations) ──► Encryption Key
                              ▲
                              │
                         Random Salt
                    (stored in vault_config.json)
```

The master password is **never** stored — not even hashed. Instead:

1. On first run, a random salt is generated and a key is derived from your master password + that salt via PBKDF2.
2. That key encrypts a known "canary" string, which is saved.
3. On every future login, your entered password re-derives a key the same way, and we try decrypting the canary. If it decrypts to the expected value, the password was correct — and that same derived key is then used to decrypt your actual entries.

This means there's no separate password hash that could ever drift out of sync with your actual encryption key — verification and decryption use the exact same derivation.

Every individual credential's password field — and its TOTP secret, if it has one — is encrypted independently with Fernet before being written to SQLite, so even direct access to `vault.db` reveals nothing useful without the master password.

## Installation

```bash
git clone <this-repo>
cd vaultkeeper
pip install -r requirements.txt
```

**Optional:** install as a CLI command (`vaultkeeper` instead of `python -m vaultkeeper.main`):

```bash
pip install -e .
```

> **Clipboard support on Linux:** `pyperclip` needs a backend like `xclip` or `xsel` installed (`sudo apt install xclip`). Without one, VaultKeeper will warn you and you can still use `--show` to view passwords directly.

## Usage

### First run

The very first command you run will walk you through creating a master password:

```bash
python -m vaultkeeper.main list
```

```
No vault found. Let's set one up.

Create a master password (min 10 characters): 
Confirm master password: 
✔ Vault created successfully. You're ready to go!
```

### Adding an entry

```bash
# Provide your own password
python -m vaultkeeper.main add --service GitHub --username ali@example.com --password "MyP@ssw0rd!"

# Or let VaultKeeper generate one for you
python -m vaultkeeper.main add --service Gmail --username ali@gmail.com --generate --length 20
```

### Retrieving an entry

```bash
# Copies password to clipboard (auto-clears after 15s)
python -m vaultkeeper.main get GitHub

# Print it directly instead
python -m vaultkeeper.main get GitHub --show
```

### Listing and searching

```bash
python -m vaultkeeper.main list
python -m vaultkeeper.main search git
```

### Updating an entry

```bash
python -m vaultkeeper.main update GitHub --password "NewP@ssw0rd!" --notes "Rotated June 2026"
```

### Rotating a password (regen)

If you've already changed the password on the website yourself, this just records it:

```bash
python -m vaultkeeper.main regen GitHub
# prompts: "Enter the new password for 'GitHub' (the one you've already set on the website):"
```

If you want VaultKeeper to generate a new one for you to go set on the website:

```bash
python -m vaultkeeper.main regen GitHub --generate --length 20
# prints the new password clearly so you can copy it into the site's "change password" form
```

### Tags

```bash
# Add an entry with a tag
python -m vaultkeeper.main add --service GitHub --username ali@example.com --generate --tag work

# List only entries with a given tag
python -m vaultkeeper.main list --tag work

# See all tags in use, with counts
python -m vaultkeeper.main tags
```

### 2FA / TOTP codes

```bash
# Add an entry with a TOTP secret (the base32 string from the site's QR setup screen)
python -m vaultkeeper.main add --service GitHub --username ali@example.com --generate --totp-secret JBSWY3DPEHPK3PXP

# get shows the live 6-digit code alongside the password
python -m vaultkeeper.main get GitHub --show
```

### Security audit

Scans your whole vault for reused and weak passwords:

```bash
python -m vaultkeeper.main audit
```

### Stale password reminders

```bash
# Show entries that haven't been updated in 180+ days
python -m vaultkeeper.main list --stale-days 180
```

### Deleting an entry

```bash
python -m vaultkeeper.main delete GitHub          # asks for confirmation
python -m vaultkeeper.main delete GitHub --yes    # skips confirmation
```

### Generating a standalone password

```bash
python -m vaultkeeper.main generate --length 24 --exclude-ambiguous
```

### Checking password strength

```bash
python -m vaultkeeper.main check-strength "correct-horse-battery-staple"
# or omit the argument to be prompted securely (input hidden):
python -m vaultkeeper.main check-strength
```

### Backing up and restoring (encrypted)

```bash
# Export (you'll be asked to set a passphrase protecting the backup file)
python -m vaultkeeper.main export ~/vaultkeeper-backup.json

# Import into this or another vault
python -m vaultkeeper.main import ~/vaultkeeper-backup.json
```

Backups use their own independent encryption (a fresh salt + key derived from the backup passphrase you set), so a backup file is self-contained and doesn't depend on your live vault's salt or master password.

### Bulk import from CSV (e.g. existing passwords from another tool)

If you already have a spreadsheet or export from elsewhere with your passwords, import it directly:

```bash
python -m vaultkeeper.main import-csv ~/my-existing-passwords.csv
```

Expected columns (header row required): `service_name`, `username`, `password`, and optionally `url`, `notes`, `tag`. Rows missing a required field are skipped (not fatal) and reported. Duplicates (same service + username already in your vault) are skipped automatically.

You can also export to CSV — note this is **plaintext**, unlike `export` above, so VaultKeeper will warn you and ask for confirmation:

```bash
python -m vaultkeeper.main export-csv ~/my-passwords-plaintext.csv
```

## Project structure

```
vaultkeeper/
├── README.md
├── requirements.txt
├── setup.py
├── .gitignore
│
├── vaultkeeper/
│   ├── main.py                   # CLI entry point, argparse dispatch
│   ├── config.py                 # paths, constants, KDF parameters
│   │
│   ├── auth/
│   │   ├── master_auth.py        # master password setup/verification (canary scheme)
│   │   └── lockout.py            # persisted brute-force throttling
│   │
│   ├── crypto/
│   │   ├── key_derivation.py     # PBKDF2HMAC key derivation
│   │   ├── cipher.py             # Fernet encrypt/decrypt wrapper
│   │   └── password_gen.py       # secrets-based password generator
│   │
│   ├── storage/
│   │   ├── database.py           # SQLite connection, schema, and migrations
│   │   ├── models.py             # Entry dataclass
│   │   ├── repository.py         # CRUD + tag/staleness queries
│   │   ├── backup.py             # encrypted export/import
│   │   └── csv_io.py             # plaintext CSV bulk import/export
│   │
│   ├── cli/
│   │   ├── commands.py           # command implementations
│   │   └── display.py            # tables, colored output, audit report
│   │
│   └── utils/
│       ├── clipboard.py          # copy + auto-clear
│       ├── strength_checker.py   # entropy-based strength scoring
│       ├── audit.py              # password reuse / weak-password scan
│       ├── totp.py                # TOTP secret validation + live code generation
│       ├── validators.py         # input validation
│       └── exceptions.py         # custom exception hierarchy
│
├── tests/                        # pytest suite (126+ tests)
│   ├── conftest.py               # isolated-temp-dir fixtures
│   ├── test_crypto.py
│   ├── test_key_derivation.py
│   ├── test_repository.py
│   ├── test_password_gen.py
│   ├── test_strength_checker.py
│   ├── test_totp.py
│   ├── test_audit.py
│   ├── test_csv_io.py
│   └── test_database_migration.py
│
└── data/                          # created at runtime — gitignored
    ├── vault.db                   # encrypted credential storage
    ├── vault_config.json          # salt + KDF params + encrypted canary
    └── lockout_state.json         # brute-force throttle state
```

## Running the tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

All storage and auth tests run against an isolated temporary directory (see `tests/conftest.py`), so running the test suite never touches your real vault.

## Security notes & limitations

This is a **moderate-level personal project**, not an audited security product. A few honest caveats:

- **No memory protection.** Python strings are immutable; plaintext passwords briefly exist in memory during encrypt/decrypt operations and aren't forcibly zeroed. A sufficiently privileged attacker with memory access could potentially recover them. This is a known limitation of pure-Python password managers in general.
- **`export-csv` writes plaintext to disk.** Unlike `export` (encrypted), CSV export exists for interoperability with spreadsheets and other tools, so it necessarily writes every password in the clear. VaultKeeper warns and asks for confirmation before doing this — delete the file securely once you're done with it.
- **Lockout is local and file-based.** It slows down brute-forcing via the CLI itself, but doesn't protect against someone copying `vault.db` and `vault_config.json` and attacking the key derivation offline. The 260,000 PBKDF2 iterations make that slow, but not impossible with enough compute — choose a genuinely strong, long master password.
- **No multi-user or sync support.** This is a single-user, single-machine tool by design.
- **Back up `vault_config.json` along with `vault.db`.** Losing the salt means your encrypted entries become permanently undecryptable, even if you remember your master password.

If you outgrow this tool, consider an audited, actively maintained password manager for anything beyond personal/learning use.

## License

MIT — do whatever you'd like with this.
