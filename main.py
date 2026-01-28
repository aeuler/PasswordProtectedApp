import os
import json
import base64
import hashlib
import getpass
import time
import random
from typing import Dict, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# =========================
# Config
# =========================
DEBUG = False  # Set True for developer-facing info

PEM_DIR = "pem_store"
PEM_HEADER = "-----BEGIN ENCRYPTED TEXT RECORD-----"
PEM_FOOTER = "-----END ENCRYPTED TEXT RECORD-----"

LOCKOUT_LIMIT = 5
COOLDOWN_SECONDS = 10 * 60  # 10 minutes
FAIL_DELAY_MIN = 0.2
FAIL_DELAY_MAX = 0.6

# =========================
# Runtime state (per run)
# =========================
# Cache keyed by text_id (sha256 of phrase bytes). Stores only salt+ciphertext (no plaintext).
storage: Dict[str, Dict[str, bytes]] = {}

# Rate limiting + cooldown per fingerprint (per run)
failed_attempts: Dict[str, int] = {}
lockouts: Dict[str, float] = {}  # text_id -> lockout_until_epoch


# =========================
# Helpers
# =========================
def ensure_pem_dir() -> None:
    os.makedirs(PEM_DIR, exist_ok=True)


def now() -> float:
    return time.time()


def format_seconds(secs: float) -> str:
    secs = max(0, int(secs))
    m, s = divmod(secs, 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def overwrite_bytearray(buf: bytearray) -> None:
    # Best-effort overwrite of mutable buffers
    for i in range(len(buf)):
        buf[i] = 0


def sha256_id(text_bytes: bytes) -> str:
    return hashlib.sha256(text_bytes).hexdigest()


def random_failure_delay() -> None:
    # Throttle online guessing without changing UX much
    time.sleep(random.uniform(FAIL_DELAY_MIN, FAIL_DELAY_MAX))


def derive_key_scrypt(password_bytes: bytes, salt: bytes) -> bytes:
    # Memory-hard KDF
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,  # 16384
        r=8,
        p=1,
        backend=default_backend(),
    )
    key_raw = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key_raw)  # Fernet expects this encoding


def encrypt_bytes(plaintext: bytes, password_bytes: bytes) -> Dict[str, bytes]:
    salt = os.urandom(16)
    key = derive_key_scrypt(password_bytes, salt)
    ciphertext = Fernet(key).encrypt(plaintext)
    return {"salt": salt, "ciphertext": ciphertext}


def decrypt_to_bytes(ciphertext: bytes, password_bytes: bytes, salt: bytes) -> bytes:
    key = derive_key_scrypt(password_bytes, salt)
    return Fernet(key).decrypt(ciphertext)


def pem_path(tid: str) -> str:
    return os.path.join(PEM_DIR, f"record_{tid}.pem")


def export_record_to_pem(tid: str, salt: bytes, ciphertext: bytes) -> str:
    """
    PEM-like envelope storing JSON payload (base64) with salt+ciphertext.
    """
    ensure_pem_dir()
    payload = {
        "version": 1,
        "text_id": tid,
        "kdf": "scrypt",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    b64 = base64.b64encode(payload_bytes).decode("ascii")

    # wrap at 64 chars (PEM style)
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    pem_text = "\n".join([PEM_HEADER, *lines, PEM_FOOTER, ""])

    path = pem_path(tid)
    with open(path, "w", encoding="utf-8") as f:
        f.write(pem_text)
    return path


def import_record_from_pem(tid: str) -> Optional[Dict[str, bytes]]:
    """
    Silent import: returns None for missing/invalid/corrupt files.
    (Avoids leaking existence details in messaging.)
    """
    path = pem_path(tid)
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not (content.startswith(PEM_HEADER) and content.endswith(PEM_FOOTER)):
            return None

        body = content[len(PEM_HEADER) :]
        body = body[: body.rfind(PEM_FOOTER)]
        body = body.strip().replace("\n", "")

        payload_bytes = base64.b64decode(body)
        payload = json.loads(payload_bytes.decode("utf-8"))

        if payload.get("kdf") != "scrypt":
            return None

        salt = base64.b64decode(payload["salt_b64"])
        ciphertext = base64.b64decode(payload["ciphertext_b64"])
        return {"salt": salt, "ciphertext": ciphertext}
    except Exception:
        return None


def prompt_password_bytes(prompt: str) -> bytearray:
    """
    getpass returns str (immutable). Convert ASAP to bytearray so we can overwrite.
    """
    pw_str = getpass.getpass(prompt)
    pw_buf = bytearray(pw_str.encode("utf-8"))
    pw_str = None  # drop reference quickly
    return pw_buf


def check_and_maybe_clear_lockout(tid: str) -> Tuple[bool, float]:
    """
    Returns (locked, remaining_seconds).
    If expired, clears lockout and resets attempts for this fingerprint.
    """
    until = lockouts.get(tid)
    if until is None:
        return False, 0.0

    t = now()
    if t >= until:
        lockouts.pop(tid, None)
        failed_attempts.pop(tid, None)
        return False, 0.0

    return True, until - t


def list_fingerprints() -> Tuple[str, ...]:
    """
    Return available fingerprint IDs from PEM_DIR.
    Shows only IDs; no plaintext, no labels.
    """
    if not os.path.isdir(PEM_DIR):
        return tuple()
    ids = []
    for name in os.listdir(PEM_DIR):
        if name.startswith("record_") and name.endswith(".pem"):
            tid = name[len("record_") : -len(".pem")]
            if len(tid) == 64 and all(c in "0123456789abcdef" for c in tid):
                ids.append(tid)
    ids.sort()
    return tuple(ids)


# =========================
# Flows
# =========================
def protect_flow() -> None:
    phrase = input("Enter a NEW phrase to protect (encrypt): ")
    if not phrase.strip():
        print("Nothing entered.\n")
        return

    # Convert to mutable buffer ASAP; drop str reference
    text_buf = bytearray(phrase.encode("utf-8"))
    phrase = None

    tid = sha256_id(bytes(text_buf))

    # Avoid overwriting existing records; keep messaging generic
    if tid in storage or os.path.exists(pem_path(tid)):
        print("Not creating a new record (a stored entry already exists for that fingerprint).\n")
        overwrite_bytearray(text_buf)
        return

    pw = prompt_password_bytes("Create a password to encrypt & save: ")
    if len(pw) == 0:
        print("Password cannot be empty.\n")
        overwrite_bytearray(text_buf)
        overwrite_bytearray(pw)
        return

    record = encrypt_bytes(bytes(text_buf), bytes(pw))
    storage[tid] = record
    export_path = export_record_to_pem(tid, record["salt"], record["ciphertext"])

    # Reset rate-limiting state for this tid on successful creation
    failed_attempts.pop(tid, None)
    lockouts.pop(tid, None)

    # Wipe sensitive buffers ASAP
    overwrite_bytearray(text_buf)
    overwrite_bytearray(pw)

    if DEBUG:
        print(f"[DEBUG] Saved encrypted record to: {export_path}")
        print(f"[DEBUG] Fingerprint (SHA-256): {tid}\n")
    else:
        # Show fingerprint so user can later decrypt by password-only flow
        print(f"Saved. Fingerprint (SHA-256): {tid}\n")


def decrypt_flow() -> None:
    # Password-only decrypt requires selecting WHICH record to decrypt.
    # We'll ask for a fingerprint (or let them list and pick).
    fps = list_fingerprints()
    if not fps:
        print("No stored records found.\n")
        return

    print("Stored fingerprints (SHA-256):")
    # Show shortened prefixes for readability, but accept full input
    for i, tid in enumerate(fps, start=1):
        print(f"  {i}) {tid[:12]}...")

    choice = input("Select a record number (or paste full SHA-256): ").strip().lower()
    if not choice:
        print("Nothing selected.\n")
        return

    if choice.isdigit():
        idx = int(choice)
        if idx < 1 or idx > len(fps):
            print("Invalid selection.\n")
            return
        tid = fps[idx - 1]
    else:
        tid = choice
        if len(tid) != 64 or any(c not in "0123456789abcdef" for c in tid):
            print("Invalid SHA-256 fingerprint.\n")
            return

    locked, remaining = check_and_maybe_clear_lockout(tid)
    if locked:
        print("Locked out. Try again later.\n")
        if DEBUG:
            print(f"[DEBUG] Lockout remaining: {format_seconds(remaining)} (fingerprint={tid})\n")
        return

    # Load record silently (don't reveal existence beyond what listing already implies)
    record = storage.get(tid)
    if record is None:
        record = import_record_from_pem(tid)
        if record is not None:
            storage[tid] = record

    attempts = failed_attempts.get(tid, 0)
    pw = prompt_password_bytes("Enter password to decrypt: ")

    try:
        if record is None:
            raise InvalidToken()

        pt_bytes = decrypt_to_bytes(record["ciphertext"], bytes(pw), record["salt"])
        print("Plaintext:", pt_bytes.decode("utf-8"), "\n")

        failed_attempts.pop(tid, None)
        lockouts.pop(tid, None)

        pt_bytes = None
    except (InvalidToken, Exception):
        random_failure_delay()

        attempts += 1
        failed_attempts[tid] = attempts

        # Show fingerprint on failure (as requested previously)
        print(f"SHA-256 fingerprint: {tid}")

        if attempts >= LOCKOUT_LIMIT:
            lockouts[tid] = now() + COOLDOWN_SECONDS
            print("Locked out. Try again later.\n")
            if DEBUG:
                print(f"[DEBUG] Lockout set for {format_seconds(COOLDOWN_SECONDS)} (fingerprint={tid})\n")
        else:
            print("Decrypt failed. Try again.\n")
            if DEBUG:
                remaining_attempts = LOCKOUT_LIMIT - attempts
                print(f"[DEBUG] Remaining attempts before cooldown: {remaining_attempts} (fingerprint={tid})\n")
    finally:
        overwrite_bytearray(pw)


def main() -> None:
    if DEBUG:
        print("[DEBUG] Text Protector running")
        print(
            f"[DEBUG] Rate limit={LOCKOUT_LIMIT}, cooldown={format_seconds(COOLDOWN_SECONDS)}, "
            f"fail_delay={int(FAIL_DELAY_MIN*1000)}–{int(FAIL_DELAY_MAX*1000)} ms\n"
        )

    while True:
        print("Choose an option:")
        print("  1) Protect")
        print("  2) Decrypt")
        print("  3) Exit")
        choice = input("> ").strip()

        if choice == "1":
            protect_flow()
        elif choice == "2":
            decrypt_flow()
        elif choice == "3":
            break
        else:
            print("Invalid choice.\n")


if __name__ == "__main__":
    main()