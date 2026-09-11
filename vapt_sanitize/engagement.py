from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:  # optional unless engagement vaults are used
    Fernet = None

    class InvalidToken(Exception):
        pass

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None


VAULT_VERSION = 1
ENGAGEMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PLACEHOLDER_RE = re.compile(r"^\[[A-Z0-9_]+_\d{3,}\]$")


class EngagementError(Exception):
    """Raised when an engagement vault cannot be used safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def config_root() -> Path:
    explicit = os.environ.get("VAPT_SANITIZE_CONFIG_DIR")
    if explicit:
        return Path(explicit).expanduser()

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg).expanduser() / "vapt-sanitize"

    return Path.home() / ".config" / "vapt-sanitize"


def data_root() -> Path:
    explicit = os.environ.get("VAPT_SANITIZE_DATA_DIR")
    if explicit:
        return Path(explicit).expanduser()

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "vapt-sanitize"

    return Path.home() / ".local" / "share" / "vapt-sanitize"


def engagements_root() -> Path:
    return data_root() / "engagements"


def validate_engagement_id(engagement_id: str) -> str:
    value = engagement_id.strip()

    if not ENGAGEMENT_ID_RE.fullmatch(value):
        raise EngagementError(
            "Invalid engagement ID. Use 1-64 characters: letters, numbers, '.', '_' or '-'."
        )

    return value


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    _ensure_private_dir(path.parent)
    temp_path = path.with_name(path.name + ".tmp")

    try:
        with open(temp_path, "wb") as handle:
            os.chmod(temp_path, mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_path, path)
        os.chmod(path, mode)

    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _master_key_path() -> Path:
    return config_root() / "master.key"


def _require_crypto() -> None:
    if Fernet is None:
        raise EngagementError(
            "Engagement vaults require the 'cryptography' package. "
            "Install it in the vapt-sanitize virtual environment first."
        )


def _load_master_key(*, create: bool) -> bytes:
    _require_crypto()
    path = _master_key_path()

    if path.exists():
        if not path.is_file():
            raise EngagementError(f"Master key path is not a file: {path}")

        key = path.read_bytes().strip()

        try:
            Fernet(key)
        except Exception as exc:
            raise EngagementError("Master key is invalid or corrupted.") from exc

        return key

    if not create:
        raise EngagementError(
            f"Master key not found: {path}. Existing engagement mappings cannot be decrypted."
        )

    _ensure_private_dir(path.parent)
    key = Fernet.generate_key()

    try:
        # O_EXCL avoids racing another process creating a different key.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _load_master_key(create=False)

    with os.fdopen(fd, "wb") as handle:
        handle.write(key + b"\n")
        handle.flush()
        os.fsync(handle.fileno())

    return key


class EngagementVault:
    """Encrypted, engagement-scoped pseudonym mapping.

    Only pseudonymized values belong here. Redacted secrets must never be added.
    """

    def __init__(self, engagement_id: str, directory: Path, key: bytes, data: dict):
        _require_crypto()
        self.engagement_id = validate_engagement_id(engagement_id)
        self.directory = directory
        self.mapping_path = directory / "mapping.enc"
        self.metadata_path = directory / "metadata.json"
        self._fernet = Fernet(key)
        self._data = data
        self._dirty = False
        self._lock_handle = None
        self._reverse: dict[tuple[str, str], str] = {}
        self._by_placeholder: dict[str, dict] = {}
        self._rebuild_indexes()

    def _decrypt_mapping(self) -> dict:
        encrypted = self.mapping_path.read_bytes()

        try:
            plaintext = self._fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise EngagementError(
                "Engagement mapping could not be decrypted. The key is wrong or the vault is corrupted."
            ) from exc

        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EngagementError("Engagement mapping is corrupted.") from exc

        self._validate_data(data, self.engagement_id)
        return data

    def begin_session(self) -> None:
        if self._lock_handle is not None:
            raise EngagementError("Engagement mapping session is already active.")

        lock_path = self.directory / ".mapping.lock"
        _ensure_private_dir(self.directory)
        handle = open(lock_path, "a+b")
        try:
            os.chmod(lock_path, 0o600)
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            elif msvcrt is not None:  # pragma: no cover - Windows
                handle.seek(0)
                if handle.read(1) == b"":
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:  # pragma: no cover
                raise EngagementError("No supported file-lock backend is available.")

            self._lock_handle = handle
            self._data = self._decrypt_mapping()
            self._dirty = False
            self._rebuild_indexes()

        except Exception:
            try:
                handle.close()
            finally:
                self._lock_handle = None
            raise

    def end_session(self) -> None:
        handle = self._lock_handle
        if handle is None:
            return

        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:  # pragma: no cover - Windows
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            handle.close()
            self._lock_handle = None

    @classmethod
    def create(cls, engagement_id: str) -> "EngagementVault":
        engagement_id = validate_engagement_id(engagement_id)
        directory = engagements_root() / engagement_id
        mapping_path = directory / "mapping.enc"
        metadata_path = directory / "metadata.json"

        if mapping_path.exists() or metadata_path.exists() or directory.exists():
            raise EngagementError(f"Engagement already exists: {engagement_id}")

        _ensure_private_dir(directory)
        key = _load_master_key(create=True)
        now = _utc_now()
        data = {
            "version": VAULT_VERSION,
            "engagement_id": engagement_id,
            "created_at": now,
            "updated_at": now,
            "counters": {},
            "entries": [],
        }

        vault = cls(engagement_id, directory, key, data)
        vault._dirty = True
        vault.save()
        vault._write_metadata()
        return vault

    @classmethod
    def open(cls, engagement_id: str) -> "EngagementVault":
        engagement_id = validate_engagement_id(engagement_id)
        directory = engagements_root() / engagement_id
        mapping_path = directory / "mapping.enc"

        if not mapping_path.is_file():
            raise EngagementError(
                f"Engagement not found: {engagement_id}. Create it first with 'engagement init'."
            )

        key = _load_master_key(create=False)
        encrypted = mapping_path.read_bytes()

        try:
            plaintext = Fernet(key).decrypt(encrypted)
        except InvalidToken as exc:
            raise EngagementError(
                "Engagement mapping could not be decrypted. The key is wrong or the vault is corrupted."
            ) from exc

        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EngagementError("Engagement mapping is corrupted.") from exc

        cls._validate_data(data, engagement_id)
        return cls(engagement_id, directory, key, data)

    @staticmethod
    def _validate_data(data: dict, engagement_id: str) -> None:
        if not isinstance(data, dict):
            raise EngagementError("Engagement mapping root is invalid.")

        if data.get("version") != VAULT_VERSION:
            raise EngagementError("Unsupported engagement mapping version.")

        if data.get("engagement_id") != engagement_id:
            raise EngagementError("Engagement mapping ID does not match its directory.")

        if not isinstance(data.get("counters"), dict):
            raise EngagementError("Engagement counters are invalid.")

        if not isinstance(data.get("entries"), list):
            raise EngagementError("Engagement entries are invalid.")

        seen_placeholders = set()
        seen_keys = set()

        for entry in data["entries"]:
            if not isinstance(entry, dict):
                raise EngagementError("Engagement entry is invalid.")

            category = entry.get("category")
            canonical = entry.get("canonical")
            placeholder = entry.get("placeholder")
            originals = entry.get("originals")

            if not all(isinstance(item, str) and item for item in (category, canonical, placeholder)):
                raise EngagementError("Engagement entry contains invalid values.")

            if not PLACEHOLDER_RE.fullmatch(placeholder):
                raise EngagementError("Engagement entry contains an invalid placeholder.")

            if not isinstance(originals, list) or not originals or not all(
                isinstance(item, str) and item for item in originals
            ):
                raise EngagementError("Engagement entry originals are invalid.")

            key = (category, canonical)
            if key in seen_keys or placeholder in seen_placeholders:
                raise EngagementError("Engagement mapping contains duplicate entries.")

            seen_keys.add(key)
            seen_placeholders.add(placeholder)

    def _rebuild_indexes(self) -> None:
        self._validate_data(self._data, self.engagement_id)
        self._reverse.clear()
        self._by_placeholder.clear()

        for entry in self._data["entries"]:
            key = (entry["category"], entry["canonical"])
            self._reverse[key] = entry["placeholder"]
            self._by_placeholder[entry["placeholder"]] = entry

    @property
    def counters(self) -> dict[str, int]:
        return dict(self._data["counters"])

    @property
    def reverse_mapping(self) -> dict[tuple[str, str], str]:
        return dict(self._reverse)

    def get_or_create_placeholder(
        self,
        category: str,
        canonical: str,
        original: str,
    ) -> str:
        key = (category, canonical)
        existing = self._reverse.get(key)

        if existing is not None:
            entry = self._by_placeholder[existing]
            if original not in entry["originals"]:
                entry["originals"].append(original)
                self._dirty = True
            return existing

        counter = int(self._data["counters"].get(category, 0)) + 1
        placeholder = f"[{category}_{counter:03d}]"

        while placeholder in self._by_placeholder:
            counter += 1
            placeholder = f"[{category}_{counter:03d}]"

        self._data["counters"][category] = counter
        entry = {
            "category": category,
            "canonical": canonical,
            "placeholder": placeholder,
            "originals": [original],
        }
        self._data["entries"].append(entry)
        self._reverse[key] = placeholder
        self._by_placeholder[placeholder] = entry
        self._dirty = True
        return placeholder

    def resolve(self, placeholder: str) -> list[str]:
        entry = self._by_placeholder.get(placeholder.strip())
        if entry is None:
            raise EngagementError(
                f"Placeholder not found in engagement {self.engagement_id}: {placeholder}"
            )
        return list(entry["originals"])

    def entries(self) -> list[dict]:
        return [
            {
                "placeholder": entry["placeholder"],
                "category": entry["category"],
                "originals": list(entry["originals"]),
            }
            for entry in self._data["entries"]
        ]

    def save(self) -> None:
        if not self._dirty and self.mapping_path.exists():
            return

        self._data["updated_at"] = _utc_now()
        plaintext = json.dumps(
            self._data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        encrypted = self._fernet.encrypt(plaintext)
        _atomic_write(self.mapping_path, encrypted, 0o600)
        self._dirty = False

    def _write_metadata(self) -> None:
        metadata = {
            "version": VAULT_VERSION,
            "engagement_id": self.engagement_id,
            "created_at": self._data["created_at"],
        }
        payload = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _atomic_write(self.metadata_path, payload, 0o600)

    def __enter__(self) -> "EngagementVault":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None:
                self.save()
        finally:
            self.end_session()
