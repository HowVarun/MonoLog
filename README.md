# SecureVault (MonoLog)

An offline-first, post-quantum encrypted file vault. Everything you store lives inside a single
`.scaf` container file — encrypted, versioned, and self-describing — and multiple devices keep
their containers in sync directly over the local network. There is no server, no cloud account,
and no plaintext on disk at any point.

> **Status: working prototype.** The crypto is built on standard primitives (NIST FIPS 203/204,
> AES-256-GCM, Argon2id) but the implementation has not been independently audited. Don't store
> anything you can't afford to lose yet.

---

## What it does

- **One file per vault.** A `.scaf` container holds the encrypted file cargo, the encrypted
  metadata map, the wrapped master key, and nothing else readable.
- **Two-factor key derivation.** A long Master Password and a short Weak PIN are chained through
  two Argon2id passes — the PIN derives the salt for the password's KDF, so neither secret alone
  produces the key.
- **Versioned, append-only storage.** Files are addressed by `(UUIDv7, version timestamp)`.
  Edits and deletes never overwrite cargo; old versions stay recoverable until you vacuum.
- **Ghost Mode editing.** Opening a file decrypts it to a random-named path inside a temporary
  directory, launches your OS default application, then re-ingests changes and zero-overwrites the
  plaintext on close.
- **Post-quantum peer sync.** Devices find each other over mDNS, authenticate with ML-DSA-87
  signatures, establish a shared secret with ML-KEM-1024, confirm it out-of-band with a 6-digit
  SAS PIN, and then exchange only the deltas each side is missing.
- **Vault-bound trust.** A peer is trusted for a *specific* vault, identified by a zero-knowledge
  `VAULT_ID` derived from the DEK. Two devices holding different vaults cannot sync, ever.
- **Key rotation and severance.** Rotating the master key re-encrypts all live cargo under a fresh
  DEK, which changes the `VAULT_ID` and cryptographically isolates every previously paired device.

---

## Architecture

### The `.scaf` container

```
Bytes 0   – 22    Zone 0  Header     "SCAF" magic, version (major/minor/patch), 16-byte KDF salt
Bytes 23  – 82    Zone 1  Lockbox    12-byte IV + 48-byte AES-GCM wrapped DEK
Bytes 83  – 126   Zone 2  Pointer    Encrypted (offset, length) of the metadata map
Bytes 127 – EOF   Zone 3  Stream     Encrypted file chunks, then the encrypted metadata map
```

The KEK (derived from your two passwords) only ever unwraps the DEK in Zone 1. The DEK encrypts
everything else: cargo chunks, the metadata map, the map pointer, and the sync ledger. Changing
your password re-wraps the DEK and touches nothing else.

Zone 1, 2, and 3 writes go through atomic swap helpers that leave a `.als` / `.ams` / `.ahs`
sidecar until the write is fsynced. `VaultIO.rescue_vault()` replays those sidecars if the process
dies mid-write.

### Metadata

Two representations of the same index, kept in step:

- `VaultMap` — a msgpack dictionary mapping a 24-byte `(uuid, v_ts)` file ID to its chunk list
  (`iv`, `start`, `end`). This is what gets encrypted into Zone 3.
- `VaultDatabase` — an **in-memory** SQLite table over the same records, giving indexed lookups by
  virtual path and parent folder for the directory browser. It never touches disk.

### Runtime layout

| Module | Role |
| --- | --- |
| `modules/crypto_core` | Argon2id KDF, AES-256-GCM engine, SHA3-256 hashing, ML-DSA/ML-KEM wrappers, SAS PIN derivation |
| `modules/system` | `.scaf` byte-level I/O, ghost-file lifecycle, OS keyring identity storage, opcode dictionary |
| `modules/vaultmap` | Encrypted metadata map and the in-memory SQLite index |
| `modules/orchestrator` | `VaultManager` (lifecycle, ingest, stream, rename, delete, restore) and `VaultDynamicManager` (vacuum, key rotation, password change, transit packaging, self-destruct) |
| `modules/daemons` | `TaSkewer` task queue, `SyncLedger`, `SyncWorker` network engine, `Defragmentation` |
| `modules/network` | mDNS discovery, QR pairing payloads, TCP transport framing, trusted-devices database |

All mutating vault operations are pushed onto **TaSkewer**, a single background worker thread, so
the CLI never blocks and writes are serialized against the vault's I/O lock.

### Sync protocol

Every message on the wire is `[4-byte big-endian payload length][5-byte opcode][payload]`. Opcodes
are grouped by letter — `R` routing, `I` identity/pairing, `V` vault data, `S` sync control,
`N` nuclear, `X` teardown, `E` errors — and documented in full in
`modules/system/opcodes.py`.

The pairing and sync flow, briefly:

1. Host broadcasts `_securevault._tcp.local.` with its ML-DSA public key hash. Broadcasting
   requires an unlocked vault.
2. Client connects, exchanges `PING`/`PONG` with 8 random bytes to prove liveness.
3. `TRUST_QRY` with the peer's key hash takes either the fast path (already trusted → sync) or
   the pairing path.
4. Pairing: full ML-DSA public keys are exchanged and hash-verified, an ML-KEM-1024 encapsulation
   produces a shared secret, and both sides derive the same 6-digit SAS PIN via HKDF. The user
   confirms the PIN on both devices.
5. Sync: each side sends its unsynced ledger, an auditor compares `(data_ts, meta_ts, is_deleted)`
   per UUID, and only the genuinely newer records are pulled. Simultaneous divergent edits fork
   into a conflicted copy under a new UUIDv7 rather than silently losing a version.
6. A vault binds at most **5** peers; a sixth gets `PAIR_FULL` and the link is dropped.

Device identity is an ML-DSA-87 keypair stored in the OS credential manager (Windows Credential
Manager / macOS Keychain / Secret Service), split into base64 micro-chunks to work around keyring
value-length limits.

Full protocol reference: `Guidebooks/Network-Specification-v4.0.txt`.

---

## Setup

Requires **Python 3.10+** (the code uses `X | None` annotations and `tuple[bytes, bytes]`).

```bash
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

pip install -r requirements.txt
```

### liboqs

`liboqs-python` is a binding only — it needs the `liboqs` shared library present on the system.
Either install a prebuilt `liboqs` for your platform, or build it from source:

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --config Release
cmake --build liboqs/build --target install
```

On first import, `liboqs-python` will look for the library on the standard search path (and will
offer to fetch and build it into `~/_oqs` if it finds nothing).

The algorithms used are `ML-DSA-87` (signatures) and `ML-KEM-1024` (key encapsulation); both must
be enabled in your `liboqs` build.

---

## Running it

```bash
python app2.py
```

Vaults are created in and loaded from the `Vaults/` directory.

**Start menu**

1. Create New Vault — prompts for a Master Password and a Weak PIN
2. Unlock Existing Vault
3. Clone / Import Vault from Peer — bootstraps a brand-new device over the network
4. Exit

**Vault menu**

| | |
| --- | --- |
| 1 | Add a file (ingest) |
| 2 | Open / edit a file (Ghost Mode) |
| 3 | Delete a file (soft) |
| 4 | Rename a file |
| 5 | Restore a deleted or archived version |
| 6 | View the network sync ledger |
| 7 | Run defragmentation (vacuum) |
| 8 | Rotate the master encryption key (sever & isolate) |
| 9 | Change the vault password |
| 10 | Lock and close the vault |
| 11 | Network sync, pairing and device manager |

Option 11 runs the `SyncWorker` in either server mode (wait for an incoming peer) or client mode
(scan the LAN and connect), and exposes the trusted-devices manager: nicknames, pause/resume sync,
soft unpair, and the compromised-device flag that arms the dead man's switch.

`app.py` is the earlier single-process CLI, kept in the repo for reference. `app2.py` is the
current entry point.

### Testing two nodes on one machine

Set `SV_NODE` before launching. It offsets the listening port, namespaces the keyring identity, and
gives each node its own trusted-devices database:

```powershell
$env:SV_NODE = "2"; python app2.py    # listens on 65433, separate identity
```

Leave it unset (or `1`) for normal use on port 65432.

---

## Repository layout

```
app2.py                      Current CLI entry point
app.py                       Earlier CLI, retained for reference
modules/                     Library code (see Architecture)
Tests/                       Standalone scripts exercising crypto, sync and the PQC handshake
Guidebooks/                  Design guidebooks (PDF) and the network protocol specifications
Sample_files/                Fixtures for ingest testing
Vaults/                      Vault containers created at runtime (git-ignored)
requirements.txt
```

Git-ignored by design: `venv/`, `Putty_keys/`, `Vaults/`, `*.scaf`, `*.db`, `Guidebooks/`, `dev/`.

---

## Cryptographic summary

| Purpose | Primitive |
| --- | --- |
| Key derivation | Argon2id, chained twice (PIN → salt, password → KEK), 64 MiB / 2 iterations / 4 lanes |
| Data encryption | AES-256-GCM, per-chunk 96-bit IV, 2 MiB chunks |
| Hashing | SHA3-256 |
| Device identity | ML-DSA-87 (NIST FIPS 204) |
| Peer key exchange | ML-KEM-1024 (NIST FIPS 203) |
| SAS PIN | HKDF-SHA3-256 over the sorted public keys, reduced to 6 digits |
| Vault identity | `SHA3-256(b"MONOLOG_VAULT_ID:" + DEK)` |

Secrets held in RAM are kept in `bytearray`s and zero-overwritten on lock, and decrypted ghost
files are overwritten with zeros before deletion.

---

## Known limitations

- CLI only; no GUI. The mobile QR discovery path is scaffolded but not wired into a mobile client.
- The in-memory SQLite index means vault size is bounded by available RAM for metadata (not for
  file cargo, which streams).
- `modules/network/pairing.py` is superseded by the handshake inside `SyncWorker` and is not used
  by the current flow.
- Debug output is still printed on several paths, including parts of discovery and vault locking.
