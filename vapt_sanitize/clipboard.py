import os
import shutil
import subprocess
from abc import ABC, abstractmethod


class ClipboardError(Exception):
    """Raised when clipboard access fails."""


class ClipboardBackend(ABC):
    """Abstract clipboard backend."""

    @abstractmethod
    def read(self) -> str:
        """Read text from the clipboard."""

    @abstractmethod
    def write(self, text: str) -> None:
        """Write text to the clipboard."""


def _run_command(
    command: list[str],
    *,
    input_text: str | None = None,
) -> str:
    """
    Execute a clipboard command and return stdout.
    """

    try:
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )

    except FileNotFoundError as exc:
        raise ClipboardError(
            f"Command not found: {command[0]}"
        ) from exc

    except subprocess.CalledProcessError as exc:
        message = (
            exc.stderr.strip()
            or "unknown command error"
        )

        raise ClipboardError(
            f"Clipboard command failed: {message}"
        ) from exc

    return result.stdout


class X11ClipboardBackend(ClipboardBackend):
    """
    X11 backend using xclip.

    xclip must remain alive as the X11 selection owner.
    """

    command = "xclip"

    def read(self) -> str:
        return _run_command(
            [
                self.command,
                "-selection",
                "clipboard",
                "-out",
                "-t",
                "UTF8_STRING",
            ]
        )

    def write(self, text: str) -> None:
        try:
            process = subprocess.Popen(
                [
                    self.command,
                    "-selection",
                    "clipboard",
                    "-in",
                    "-loops",
                    "0",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )

        except FileNotFoundError as exc:
            raise ClipboardError(
                "xclip not found."
            ) from exc

        if process.stdin is None:
            try:
                process.kill()
            except OSError:
                pass

            raise ClipboardError(
                "Could not open xclip stdin."
            )

        try:
            process.stdin.write(text)
            process.stdin.close()

        except (BrokenPipeError, OSError) as exc:
            try:
                process.kill()
            except OSError:
                pass

            raise ClipboardError(
                "Could not write clipboard data."
            ) from exc


class XselClipboardBackend(ClipboardBackend):
    """X11 backend using xsel."""

    command = "xsel"

    def read(self) -> str:
        return _run_command(
            [
                self.command,
                "--clipboard",
                "--output",
            ]
        )

    def write(self, text: str) -> None:
        _run_command(
            [
                self.command,
                "--clipboard",
                "--input",
            ],
            input_text=text,
        )


class WaylandClipboardBackend(ClipboardBackend):
    """Wayland backend using wl-paste and wl-copy."""

    def read(self) -> str:
        return _run_command(
            [
                "wl-paste",
                "--no-newline",
            ]
        )

    def write(self, text: str) -> None:
        _run_command(
            [
                "wl-copy",
            ],
            input_text=text,
        )


class WindowsClipboardBackend(ClipboardBackend):
    """Windows backend using PowerShell."""

    def read(self) -> str:
        return _run_command(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-Clipboard",
            ]
        )

    def write(self, text: str) -> None:
        _run_command(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "$input | Set-Clipboard",
            ],
            input_text=text,
        )


class MacOSClipboardBackend(ClipboardBackend):
    """macOS backend using pbpaste/pbcopy."""

    def read(self) -> str:
        return _run_command(
            ["pbpaste"]
        )

    def write(self, text: str) -> None:
        _run_command(
            ["pbcopy"],
            input_text=text,
        )


def _is_x11() -> bool:
    return bool(
        os.environ.get("DISPLAY")
    )


def _is_wayland() -> bool:
    return bool(
        os.environ.get("WAYLAND_DISPLAY")
    )


def _is_windows() -> bool:
    return os.name == "nt" or bool(
        shutil.which("powershell.exe")
    )


def _is_macos() -> bool:
    return (
        os.name == "posix"
        and subprocess.run(
            ["uname"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        == "Darwin"
    )


def get_clipboard_backend() -> ClipboardBackend:
    """
    Select the most appropriate clipboard backend.
    """

    # Wayland takes precedence when explicitly active.
    if _is_wayland():
        if (
            shutil.which("wl-paste")
            and shutil.which("wl-copy")
        ):
            return WaylandClipboardBackend()

    # X11.
    if _is_x11():
        if shutil.which("xclip"):
            return X11ClipboardBackend()

        if shutil.which("xsel"):
            return XselClipboardBackend()

    # Native Windows.
    if _is_windows():
        if shutil.which("powershell.exe"):
            return WindowsClipboardBackend()

    # macOS.
    if _is_macos():
        if (
            shutil.which("pbpaste")
            and shutil.which("pbcopy")
        ):
            return MacOSClipboardBackend()

    raise ClipboardError(
        "No supported clipboard backend detected. "
        "Supported environments: X11, Wayland, "
        "Windows, and macOS."
    )


def read_clipboard() -> str:
    """Read clipboard using the detected backend."""

    backend = get_clipboard_backend()

    try:
        text = backend.read()
    except ClipboardError:
        raise

    if text == "":
        raise ClipboardError(
            "Clipboard is empty or could not be read."
        )

    return text


def write_clipboard(text: str) -> None:
    """
    Write clipboard content using the detected backend.

    Empty content is rejected to prevent accidental
    clipboard destruction.
    """

    if not text:
        raise ClipboardError(
            "Refusing to write empty clipboard content."
        )

    backend = get_clipboard_backend()
    backend.write(text)


def verify_clipboard(expected: str) -> None:
    """
    Verify that clipboard contains the expected text.

    This is intentionally a separate operation so the caller
    can implement fail-closed behavior.
    """

    actual = read_clipboard()

    if actual != expected:
        raise ClipboardError(
            "Clipboard verification failed."
        )
