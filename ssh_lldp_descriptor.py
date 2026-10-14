"""
SSH Command & LLDP Tool
=======================
Connects to a batch of network devices (switches) over SSH.

Two workflows in one app:

  - "Commands to Send" tab: runs a configurable list of CLI commands against
    every target device. Sessions run concurrently (configurable "Parallel
    sessions" count). The command list is empty by default - always review
    it before starting, especially with auto-confirm enabled.

  - "LLDP-Update" tab: logs into each switch, detects the platform, reads
    the LLDP neighbors and the current port descriptions / aliases and
    proposes a per-port update:
        1. Port inactive              -> append "?" to the current
                                          description.
        2. Port active, description == LLDP neighbor system name
                                       -> no change.
        3. Port active, description != LLDP neighbor system name
                                       -> description is set to the
                                          neighbor system name.
    LLDP neighbors reported as "Not-Advertised" are ignored. Scan first,
    review the proposed changes in the table, then Apply. Devices with at
    least one applied change automatically save their configuration
    afterwards. Any row can be edited manually or marked for clearing.
    Implemented for Alcatel-Lucent Enterprise AOS6 / AOS8 and Extreme
    Networks EXOS. Fabric Engine and Huawei VRP are detected but not
    implemented yet.

Both tabs share the "Device IP Addresses" and "SSH Login" sections above
them. The full raw SSH transcript for each device/action is captured -
double-click any row in a results table to view/save it.

Requirements: see requirements.txt
Build to exe: see build_exe.bat

Version: 1.1.0 (2026-07-02)
Author:  Dominik Gawin
License: MIT
"""

import base64
import csv
import ctypes
import ipaddress
import json
import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tkinter import ttk, messagebox, filedialog, scrolledtext

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

if PARAMIKO_AVAILABLE:
    # Older network gear (e.g. Extreme EXOS x440 series switches) often
    # only offers legacy SSH algorithms - DSA/RSA(SHA1) host keys, group1
    # key exchange, CBC ciphers - that recent paramiko releases no longer
    # advertise by default. That causes connect() to fail with
    # "Incompatible ssh peer (no acceptable host key)" (or similar for
    # kex/ciphers) even though the login itself would work fine. Extend
    # paramiko's preference lists with these legacy algorithms as a
    # low-priority fallback; modern devices are unaffected since their
    # stronger algorithms still get negotiated first.
    try:
        _legacy_keys = ("ssh-rsa", "ssh-dss")
        _legacy_kex = ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
                       "diffie-hellman-group-exchange-sha1")
        _legacy_ciphers = ("aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc")

        for _algo in _legacy_keys:
            if _algo not in paramiko.Transport._preferred_keys:
                paramiko.Transport._preferred_keys += (_algo,)
        for _algo in _legacy_kex:
            if _algo not in paramiko.Transport._preferred_kex:
                paramiko.Transport._preferred_kex += (_algo,)
        for _algo in _legacy_ciphers:
            if _algo not in paramiko.Transport._preferred_ciphers:
                paramiko.Transport._preferred_ciphers += (_algo,)
    except Exception:
        pass

    try:
        # Recent paramiko releases (>= 3.3) dropped the SHA-1 signature
        # mapping for plain "ssh-rsa" host keys (deprecated for security
        # reasons), which raises a bare KeyError('ssh-rsa') deep inside
        # RSAKey signature verification when talking to devices that only
        # offer that legacy algorithm (e.g. older Extreme EXOS switches).
        # Restore the mapping so verification can proceed.
        from cryptography.hazmat.primitives import hashes as _crypto_hashes
        if hasattr(paramiko.RSAKey, "HASHES") and "ssh-rsa" not in paramiko.RSAKey.HASHES:
            paramiko.RSAKey.HASHES["ssh-rsa"] = _crypto_hashes.SHA1
    except Exception:
        pass

DEFAULT_COMMANDS = ""  # intentionally empty - enter your own commands
DEFAULT_CONFIRM_PATTERN = r"\(Y/N\)|\[y/N\]|\(y/n\)|\[Y/n\]|\(y/N\)|\[y/n\]"

APP_VERSION = "1.1.0"
APP_AUTHOR = "Dominik Gawin"


# ---------------------------------------------------------------------------
# Persisted settings (Device IP Addresses + SSH Login, shared by both tabs)
# ---------------------------------------------------------------------------
# Saved automatically on exit, restored automatically on the next start.
# The password is encrypted before being written to disk: on Windows via
# the current user's DPAPI profile (CryptProtectData - only decryptable by
# the same Windows user account on the same machine), falling back to a
# locally generated Fernet key file on other platforms or if DPAPI is
# unavailable. Neither approach protects against someone with full access
# to the same logged-in Windows session, but it keeps the password out of
# plain sight in the config file.

CONFIG_DIR = os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"), "SSHLLDPTool"
)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
FERNET_KEY_FILE = os.path.join(CONFIG_DIR, "config.key")
CHANGE_LOG_FILE = os.path.join(CONFIG_DIR, "lldp_change_log.csv")


def _ensure_config_dir():
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
    except Exception:
        pass


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _win32_crypt_protect(data):
    import ctypes as _ctypes
    buf = _ctypes.create_string_buffer(data, len(data))
    blob_in = _DATA_BLOB(len(data), _ctypes.cast(buf, _ctypes.POINTER(_ctypes.c_char)))
    blob_out = _DATA_BLOB()
    if not _ctypes.windll.crypt32.CryptProtectData(
        _ctypes.byref(blob_in), None, None, None, None, 0, _ctypes.byref(blob_out)
    ):
        raise _ctypes.WinError()
    try:
        return _ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _win32_crypt_unprotect(data):
    import ctypes as _ctypes
    buf = _ctypes.create_string_buffer(data, len(data))
    blob_in = _DATA_BLOB(len(data), _ctypes.cast(buf, _ctypes.POINTER(_ctypes.c_char)))
    blob_out = _DATA_BLOB()
    if not _ctypes.windll.crypt32.CryptUnprotectData(
        _ctypes.byref(blob_in), None, None, None, None, 0, _ctypes.byref(blob_out)
    ):
        raise _ctypes.WinError()
    try:
        return _ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _get_fernet_key():
    _ensure_config_dir()
    if os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, "rb") as f:
            return f.read()
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    with open(FERNET_KEY_FILE, "wb") as f:
        f.write(key)
    try:
        os.chmod(FERNET_KEY_FILE, 0o600)
    except Exception:
        pass
    return key


def encrypt_password(password):
    """Returns a scheme-prefixed base64 string safe for JSON storage, or
    "" if `password` is empty or encryption failed."""
    if not password:
        return ""
    data = password.encode("utf-8")
    if sys.platform == "win32":
        try:
            enc = _win32_crypt_protect(data)
            return "dpapi:" + base64.b64encode(enc).decode("ascii")
        except Exception:
            pass
    try:
        from cryptography.fernet import Fernet
        enc = Fernet(_get_fernet_key()).encrypt(data)
        return "fernet:" + base64.b64encode(enc).decode("ascii")
    except Exception:
        return ""


def decrypt_password(stored):
    """Reverses encrypt_password(); returns "" on any failure (e.g. the
    config file was copied to a different machine/user)."""
    if not stored:
        return ""
    try:
        scheme, _, b64data = stored.partition(":")
        raw = base64.b64decode(b64data)
        if scheme == "dpapi":
            return _win32_crypt_unprotect(raw).decode("utf-8")
        if scheme == "fernet":
            from cryptography.fernet import Fernet
            return Fernet(_get_fernet_key()).decrypt(raw).decode("utf-8")
    except Exception:
        pass
    return ""


def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    data["password"] = decrypt_password(data.get("password_enc", ""))
    data["password2"] = decrypt_password(data.get("password2_enc", ""))
    return data


def append_lldp_change_log(entries):
    """Appends applied LLDP-Update changes (Display-String and/or
    Description-String) to a persistent CSV audit log (`entries` is a list
    of dicts with keys: timestamp, ip, port, field, old, new, action,
    status) so they remain traceable across sessions, independent of the
    in-memory Log/Export in the UI."""
    if not entries:
        return
    _ensure_config_dir()
    is_new = not os.path.exists(CHANGE_LOG_FILE)
    try:
        with open(CHANGE_LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if is_new:
                writer.writerow(["Timestamp", "IP Address", "Port", "Feld", "Alter Wert",
                                  "Neuer Wert", "Aktion", "Status"])
            for e in entries:
                writer.writerow([e["timestamp"], e["ip"], e["port"], e["field"], e["old"],
                                  e["new"], e["action"], e["status"]])
    except Exception:
        pass


def save_config(values):
    """`values` is a plain dict of the fields to persist; "password" and
    "password2" keys (plaintext, in-memory only) are encrypted before
    writing to disk."""
    _ensure_config_dir()
    data = dict(values)
    password = data.pop("password", "")
    password2 = data.pop("password2", "")
    data["password_enc"] = encrypt_password(password)
    data["password2_enc"] = encrypt_password(password2)
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Low level SSH helpers (shared by both tabs)
# ---------------------------------------------------------------------------

class DeviceResult:
    def __init__(self, ip):
        self.ip = ip
        self.status = "Pending"
        self.log = ""
        self.commands_sent = 0


def read_until_idle(channel, idle_timeout, overall_timeout, auto_confirm,
                     confirm_regex, confirm_answer, raw_cb=None, on_confirm=None):
    """Read from an interactive SSH channel until no new data has arrived
    for `idle_timeout` seconds, or until `overall_timeout` is hit, or until
    the remote side closes the connection. Auto-answers Y/N style prompts
    when auto_confirm is enabled. Every raw chunk read is passed to raw_cb
    (used to build the full per-device transcript, not the live UI log)."""
    output = []
    last_data_time = time.time()
    start = time.time()
    while True:
        if time.time() - start > overall_timeout:
            output.append("\n[timeout waiting for device response]")
            break
        if channel.recv_ready():
            chunk = channel.recv(4096)
            if not chunk:
                output.append("\n[connection closed by remote host]")
                break
            text = chunk.decode(errors="ignore")
            output.append(text)
            if raw_cb:
                raw_cb(text)
            last_data_time = time.time()
            if auto_confirm and confirm_regex.search(text):
                channel.send(confirm_answer + "\n")
                output.append(confirm_answer + "\n")
                if on_confirm:
                    on_confirm()
        else:
            if channel.closed or channel.eof_received:
                output.append("\n[connection closed by remote host]")
                break
            if time.time() - last_data_time > idle_timeout:
                break
            time.sleep(0.1)
    return "".join(output)


def _ssh_connect(client, ip, port, username, password, username2, password2, event_cb):
    """Connects with (username, password); if that fails with an
    authentication error and a fallback username is configured (username2),
    retries once with (username2, password2). Raises
    paramiko.AuthenticationException if both attempts fail, or if the
    first fails and no fallback is configured."""
    try:
        client.connect(
            ip, port=port, username=username, password=password,
            timeout=10, banner_timeout=10, auth_timeout=10,
            look_for_keys=False, allow_agent=False,
        )
    except paramiko.AuthenticationException:
        if not username2:
            raise
        event_cb(
            f"Authentifizierung mit '{username}' fehlgeschlagen, "
            f"versuche Zugangsdaten 2 ('{username2}')...", "warn",
        )
        client.connect(
            ip, port=port, username=username2, password=password2,
            timeout=10, banner_timeout=10, auth_timeout=10,
            look_for_keys=False, allow_agent=False,
        )


def run_device(ip, port, username, password, commands, idle_timeout,
                overall_timeout, auto_confirm, confirm_regex, confirm_answer,
                event_cb, stop_event, username2=None, password2=None):
    """Runs the full command sequence against a single device.
    event_cb(message, level) is called for short progress notifications
    (level is one of: info, ok, warn, error) - this drives the simplified
    Running Log. The complete raw transcript is built up internally and
    returned so it can be inspected per-device. If username2 is set, it is
    tried as a fallback login when (username, password) is rejected.
    Returns (status_string, full_log_string, commands_sent)."""
    log_lines = [f"=== {ip}:{port} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n"]

    def raw(text):
        log_lines.append(text)

    def event(msg, level="info"):
        log_lines.append(f"\n[{level.upper()}] {msg}\n")
        if event_cb:
            event_cb(msg, level)

    if not PARAMIKO_AVAILABLE:
        event("paramiko ist nicht installiert", "error")
        return "Error: paramiko missing", "".join(log_lines), 0

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        event("Verbinde...")
        _ssh_connect(client, ip, port, username, password, username2, password2, event)
        event("Verbunden, oeffne Shell")
        shell = client.invoke_shell()
        time.sleep(1.0)

        # Drain initial banner / MOTD / prompt (goes to transcript only)
        read_until_idle(shell, idle_timeout, overall_timeout, auto_confirm,
                         confirm_regex, confirm_answer, raw_cb=raw)

        commands_sent = 0
        total_cmds = len([c for c in commands if c.strip()])
        for cmd in commands:
            if stop_event.is_set():
                event("Gestoppt durch Benutzer", "warn")
                break
            cmd = cmd.strip()
            if not cmd:
                continue
            event(f"Sende: {cmd}")
            raw(f"\n--- sending: {cmd} ---\n")
            shell.send(cmd + "\n")
            commands_sent += 1
            out = read_until_idle(
                shell, idle_timeout, overall_timeout, auto_confirm,
                confirm_regex, confirm_answer, raw_cb=raw,
                on_confirm=lambda a=confirm_answer: event(f"Prompt automatisch mit '{a}' bestaetigt"),
            )
            if "[connection closed by remote host]" in out:
                event("Verbindung vom Geraet getrennt")
                break

        try:
            client.close()
        except Exception:
            pass

        if commands_sent >= total_cmds:
            status = "OK"
        elif commands_sent > 0:
            status = f"OK ({commands_sent} cmd gesendet, getrennt)"
        else:
            status = "Error: keine Befehle gesendet"
        return status, "".join(log_lines), commands_sent

    except paramiko.AuthenticationException:
        event("Authentifizierung fehlgeschlagen", "error")
        return "Error: auth failed", "".join(log_lines), 0
    except Exception as e:
        event(f"Fehler: {e}", "error")
        return f"Error: {e}", "".join(log_lines), 0
    finally:
        try:
            client.close()
        except Exception:
            pass


def open_ssh_shell(ip, port, username, password, idle_timeout, overall_timeout,
                    confirm_regex, confirm_answer, raw_cb, event_cb,
                    username2=None, password2=None):
    """Connects and opens an interactive shell, draining the initial
    banner/MOTD. Returns (client, shell, banner_text) - banner_text is the
    raw output captured before any command is sent, used for vendor/
    platform auto-detection (see detect_vendor_platform). Raises on
    failure - caller is responsible for closing `client`. If username2 is
    set, it is tried as a fallback login when (username, password) is
    rejected."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    event_cb("Verbinde...")
    _ssh_connect(client, ip, port, username, password, username2, password2, event_cb)
    event_cb("Verbunden, oeffne Shell")
    shell = client.invoke_shell()
    time.sleep(1.0)
    banner = read_until_idle(shell, idle_timeout, overall_timeout, True,
                              confirm_regex, confirm_answer, raw_cb=raw_cb)
    return client, shell, banner


# ---------------------------------------------------------------------------
# LLDP-Update: vendor abstraction
# ---------------------------------------------------------------------------

class LldpPortRow:
    """One port's scan result / proposed action for the LLDP-Update tab."""

    def __init__(self, ip, port, link_state, neighbor, current_display,
                 new_display, action, reason, current_description=""):
        self.ip = ip
        self.port = port
        self.link_state = link_state
        self.neighbor = neighbor
        self.current_display = current_display
        self.new_display = new_display
        self.action = action  # "none" | "skip" | "mark_inactive" | "update"
        self.reason = reason
        self.result = ""       # "", "Applied", "Error"
        self.result_detail = ""

        # Description String has no automatic scan logic (unlike Display
        # String) - it is purely shown for reference and can be manually
        # edited in the "Neuer Description-String" column.
        self.current_description = current_description
        self.new_description = current_description

        # When manually marked for "delete" via the UI, the scan-determined
        # action/new_display/reason are stashed here so the mark can be
        # toggled back off (see App._on_lldp_mark_delete).
        self._orig_action = None
        self._orig_new_display = None
        self._orig_reason = None

    def has_description_change(self):
        return self.new_description != self.current_description

    def is_actionable(self):
        return self.action in ("mark_inactive", "update", "delete") or self.has_description_change()


def _port_sort_key(port):
    """Sort key for port identifiers, supporting plain numbers ("23"),
    stacked "slot:port" identifiers ("1:23"), and Alcatel-style
    "chassis/slot/port" identifiers ("1/1/23")."""
    s = str(port)
    sep = ":" if ":" in s else "/" if "/" in s else None
    try:
        if sep is None:
            return (int(s),)
        return tuple(int(x) for x in s.split(sep))
    except ValueError:
        return (s,)


class VendorNotImplemented(Exception):
    pass


class BaseVendorHandler:
    display_name = "Base"

    def scan(self, shell, idle_timeout, overall_timeout, confirm_regex,
              confirm_answer, raw_cb, event_cb, ip):
        raise VendorNotImplemented(self.display_name)

    def apply(self, shell, idle_timeout, overall_timeout, confirm_regex,
               confirm_answer, raw_cb, event_cb, changes):
        raise VendorNotImplemented(self.display_name)


class ExtremeVendorHandler(BaseVendorHandler):
    """Extreme Networks EXOS switches (e.g. x440 series)."""

    display_name = "Extreme Networks EXOS"

    # "disable clipaging" works on both old and new EXOS firmware (on
    # newer releases it just prints an informational deprecation note
    # "please use new command: disable cli paging" and still executes).
    # The newer "disable cli paging" syntax, however, is NOT understood by
    # older firmware ("%% Invalid input detected"), which leaves paging on
    # and corrupts every subsequent "show" command's output. Use the old,
    # universally-compatible form.
    CMD_DISABLE_PAGING = "disable clipaging"
    CMD_LLDP = "show lldp neighbors"
    CMD_DESC = "show ports description"
    CMD_PORTS = "show ports no-refresh"
    CMD_SAVE = "save"

    # Port identifiers are either a plain number ("23") or, on stacked
    # switches, "slot:port" ("1:23").
    RE_LLDP_LINE = re.compile(
        r'^(\d+(?::\d+)?)\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(\S+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$'
    )
    RE_PORT_LINE = re.compile(r'^(\d+(?::\d+)?)\s+(.*)$')

    def _send(self, shell, cmd, idle_timeout, overall_timeout, confirm_regex,
              confirm_answer, raw_cb):
        raw_cb(f"\n--- sending: {cmd} ---\n")
        shell.send(cmd + "\n")
        return read_until_idle(
            shell, idle_timeout, overall_timeout, True,
            confirm_regex, confirm_answer, raw_cb=raw_cb,
        )

    # -- parsing -----------------------------------------------------

    def parse_lldp_neighbors(self, text):
        """Port -> Neighbor System Name (including literal 'Not-Advertised')."""
        neighbors = {}
        for line in text.splitlines():
            m = self.RE_LLDP_LINE.match(line.strip('\r'))
            if m:
                neighbors[m.group(1)] = m.group(6).strip()
        return neighbors

    RE_PORT_ID = re.compile(r'^\d+(?::\d+)?$')

    def parse_ports_description(self, text):
        """Port -> (Display String, Description String) tuple, "" for
        either half if unset.

        This table has two independent columns that can each be empty.
        Splitting on whitespace cannot tell them apart: if the Display
        String is empty the line's first "word" is actually the start of
        the Description String, which would be misread as the display
        string (e.g. a Description String of "war vor dem 30.30.22 ..." on
        a port with no Display String set). Instead, the fixed-width
        column boundaries are derived from the "====  ====...  ====..."
        separator line that precedes the data rows, and each row is sliced
        by character position rather than tokenized. The Description
        String is sliced to the end of the line (not a fixed end column)
        since it can run longer than the header's nominal width."""
        result = {}
        col_spans = None
        for raw_line in text.splitlines():
            line = raw_line.rstrip('\r')
            stripped = line.strip()
            if not stripped:
                continue
            if col_spans is None:
                if set(stripped) <= set("= "):
                    col_spans = [m.span() for m in re.finditer(r'=+', line)]
                continue
            if len(col_spans) < 3:
                continue
            port_start, port_end = col_spans[0]
            display_start, display_end = col_spans[1]
            desc_start, _desc_end = col_spans[2]
            port_field = line[port_start:port_end].strip()
            if not self.RE_PORT_ID.match(port_field):
                continue
            display_field = line[display_start:display_end].strip()
            desc_field = line[desc_start:].strip()
            result[port_field] = (display_field, desc_field)
        return result

    def parse_ports_state(self, text):
        """Port -> Link State token ('A' = active, everything else counts
        as inactive). Ports missing from this output are left out of the
        dict entirely (treated as 'no data' by the caller)."""
        states = {}
        for raw_line in text.splitlines():
            line = raw_line.rstrip('\r')
            if not line.strip():
                continue
            m = self.RE_PORT_LINE.match(line)
            if not m:
                continue
            port = m.group(1)
            rest = m.group(2).strip()
            if not rest:
                continue
            parts = rest.split()
            # Anchor on the VLAN column - the first "(...)" token - rather
            # than a fixed index: when the Display String is empty (a very
            # common case for unused ports) there is one fewer leading
            # token, which would otherwise shift Port State/Link State one
            # position to the left and get silently misread.
            vlan_idx = next((i for i, tok in enumerate(parts)
                              if tok.startswith("(") and tok.endswith(")")), None)
            if vlan_idx is None or vlan_idx + 2 >= len(parts):
                continue
            states[port] = parts[vlan_idx + 2]
        return states

    @staticmethod
    def _quote_if_needed(value):
        # "?" triggers CLI help/completion if sent unquoted, so it (like
        # whitespace) needs the value wrapped in double quotes.
        if re.search(r'[\s?]', value):
            return f'"{value}"'
        return value

    # Extreme's display-string field is observed to cap out at 20
    # characters (longer values get silently truncated by the switch).
    # When a hyphen-stripped neighbor name is still too long, common long
    # words are shortened to abbreviations first (keeping the result
    # readable) before falling back to a hard cut-off as a last resort.
    DISPLAY_STRING_MAX_LEN = 20
    DISPLAY_STRING_ABBREVIATIONS = (
        ("Aussen", "Au"),
        ("Vordach", "Vd"),
        ("Lichtmast", "Lm"),
        ("Halle", "H"),
    )

    @classmethod
    def _display_string_from_neighbor(cls, neighbor, max_len=None):
        """Builds a display-string proposal from a raw LLDP neighbor name.
        Hyphens are only touched if needed to fit `max_len`: short names
        keep their hyphens as-is (e.g. "HB-H10-AP01"); a too-long name is
        first shortened via common-word abbreviations (hyphens kept, still
        readable), then - if still too long - hyphens are stripped, and
        only as a last resort hard-truncated."""
        max_len = cls.DISPLAY_STRING_MAX_LEN if max_len is None else max_len
        value = neighbor
        if len(value) <= max_len:
            return value
        for full, abbr in cls.DISPLAY_STRING_ABBREVIATIONS:
            if len(value) <= max_len:
                break
            value = value.replace(full, abbr)
        if len(value) > max_len:
            value = value.replace("-", "")
        if len(value) > max_len:
            value = value[:max_len]
        return value

    # -- workflow ------------------------------------------------------

    def scan(self, shell, idle_timeout, overall_timeout, confirm_regex,
              confirm_answer, raw_cb, event_cb, ip):
        event_cb("Deaktiviere CLI-Paging...")
        self._send(shell, self.CMD_DISABLE_PAGING, idle_timeout, overall_timeout,
                    confirm_regex, confirm_answer, raw_cb)

        event_cb("Lese LLDP-Nachbarn (show lldp neighbors)...")
        lldp_out = self._send(shell, self.CMD_LLDP, idle_timeout, overall_timeout,
                               confirm_regex, confirm_answer, raw_cb)
        neighbors = self.parse_lldp_neighbors(lldp_out)

        event_cb("Lese Port-Beschreibungen (show ports description)...")
        desc_out = self._send(shell, self.CMD_DESC, idle_timeout, overall_timeout,
                               confirm_regex, confirm_answer, raw_cb)
        port_info = self.parse_ports_description(desc_out)
        descriptions = {p: v[0] for p, v in port_info.items()}
        port_descriptions = {p: v[1] for p, v in port_info.items()}

        event_cb("Lese Port-Status (show ports no-refresh)...")
        ports_out = self._send(shell, self.CMD_PORTS, idle_timeout, overall_timeout,
                                confirm_regex, confirm_answer, raw_cb)
        states = self.parse_ports_state(ports_out)

        rows = []
        for port in sorted(descriptions.keys(), key=_port_sort_key):
            display = descriptions.get(port, "")
            neighbor = neighbors.get(port)
            # Display-string proposals keep the neighbor name's hyphens as
            # long as it fits the switch's ~20-char limit. Only if it's
            # too long are common long words abbreviated first (hyphens
            # kept for readability), then hyphens stripped if still too
            # long, and only as a last resort hard-truncated. The raw
            # neighbor name (with hyphens) is still shown as-is in
            # "Neighbor System Name".
            neighbor_target = self._display_string_from_neighbor(neighbor) if neighbor else neighbor
            link = states.get(port)

            if neighbor == "Not-Advertised":
                # Ignored unconditionally, per spec - even if the port
                # would otherwise be considered inactive.
                action, new_display = "skip", display
                reason = "Not-Advertised (ignoriert)"
            elif link is None:
                action, new_display = "skip", display
                reason = "Kein Port-Status verfuegbar"
            elif link != "A":
                if not display:
                    action, new_display = "none", display
                    reason = "Port inaktiv, aber kein Display-String gesetzt"
                elif display.endswith("?"):
                    action, new_display = "none", display
                    reason = "Bereits als inaktiv markiert"
                else:
                    action, new_display = "mark_inactive", display + "?"
                    reason = "Port inaktiv"
            elif neighbor is None:
                action, new_display = "skip", display
                reason = "Kein LLDP-Nachbar erkannt"
            elif neighbor_target == display:
                action, new_display = "none", display
                reason = "Stimmt bereits mit Neighbor System Name ueberein"
            else:
                action, new_display = "update", neighbor_target
                reason = "Weicht vom Neighbor System Name ab"

            rows.append(LldpPortRow(
                ip=ip, port=port, link_state=link or "?", neighbor=neighbor or "-",
                current_display=display, new_display=new_display,
                action=action, reason=reason,
                current_description=port_descriptions.get(port, ""),
            ))
        event_cb(f"{len(rows)} Ports ausgewertet", "ok")
        return rows

    def apply(self, shell, idle_timeout, overall_timeout, confirm_regex,
               confirm_answer, raw_cb, event_cb, changes):
        """changes: list of dicts with key "port" and optionally "display"
        and/or "description" (the new value for whichever field(s) are
        being changed for that port; empty string clears/unconfigures that
        field). Returns (applied_count, connection_ok)."""
        event_cb("Deaktiviere CLI-Paging...")
        self._send(shell, self.CMD_DISABLE_PAGING, idle_timeout, overall_timeout,
                    confirm_regex, confirm_answer, raw_cb)

        applied = 0
        for change in changes:
            port = change["port"]

            if "display" in change:
                new_display = change["display"]
                if new_display == "":
                    # Empty string is the sentinel for "clear the field"
                    # (manually marked in the table, see
                    # App._on_lldp_mark_delete / inline edit).
                    cmd = f"unconfigure ports {port} display-string"
                    event_cb(f"Port {port}: loesche Display-String")
                else:
                    value = self._quote_if_needed(new_display)
                    cmd = f"configure ports {port} display-string {value}"
                    event_cb(f"Port {port}: setze Display-String '{new_display}'")
                out = self._send(shell, cmd, idle_timeout, overall_timeout,
                                  confirm_regex, confirm_answer, raw_cb)
                if "[connection closed by remote host]" in out:
                    event_cb("Verbindung getrennt", "error")
                    return applied, False

            if "description" in change:
                new_description = change["description"]
                if new_description == "":
                    cmd = f"unconfigure ports {port} description-string"
                    event_cb(f"Port {port}: loesche Description-String")
                else:
                    value = self._quote_if_needed(new_description)
                    cmd = f"configure ports {port} description-string {value}"
                    event_cb(f"Port {port}: setze Description-String '{new_description}'")
                out = self._send(shell, cmd, idle_timeout, overall_timeout,
                                  confirm_regex, confirm_answer, raw_cb)
                if "[connection closed by remote host]" in out:
                    event_cb("Verbindung getrennt", "error")
                    return applied, False

            applied += 1

        if applied > 0:
            event_cb("Speichere Konfiguration (save)...")
            self._send(shell, self.CMD_SAVE, idle_timeout, overall_timeout,
                        confirm_regex, confirm_answer, raw_cb)
            event_cb("Konfiguration gespeichert", "ok")
        return applied, True


class AlcatelBaseVendorHandler(BaseVendorHandler):
    """Shared plumbing for Alcatel-Lucent AOS6 and AOS8. Alias set/clear and
    config save are identical between the two CLI dialects; only the
    LLDP-neighbor block header and the port/alias/link-status table command
    + column layout differ, so those are the only bits the subclasses
    override (CMD_LLDP, CMD_ALIAS, RE_LLDP_PORT, RE_ALIAS_LINE)."""

    # Neither AOS6 nor AOS8 has a clipaging-equivalent command - "show"
    # output is not paginated the way EXOS is, so there is nothing to
    # disable here.
    CMD_SAVE = "write memory flash-synchro"

    RE_SYSTEM_NAME = re.compile(r'^\s*System Name\s*=\s*(.*?),?\s*$')

    def _send(self, shell, cmd, idle_timeout, overall_timeout, confirm_regex,
              confirm_answer, raw_cb):
        raw_cb(f"\n--- sending: {cmd} ---\n")
        shell.send(cmd + "\n")
        return read_until_idle(
            shell, idle_timeout, overall_timeout, True,
            confirm_regex, confirm_answer, raw_cb=raw_cb,
        )

    # -- parsing -----------------------------------------------------

    def parse_lldp_neighbors(self, text):
        """Port -> Neighbor System Name. A System Name of "(null)" (neighbor
        detected but advertised no name) is normalised to the literal
        "Not-Advertised" so it is ignored the same way as on Extreme
        switches. Ports absent from the output entirely are simply left
        out of the dict (caller treats that as "no neighbor"). Uses the
        subclass's RE_LLDP_PORT to find each per-port block header.

        A single port can have more than one "Chassis ...:" sub-block under
        the same header (e.g. one real LLDP neighbor plus an extra agent
        that advertises no name at all) - observed on an AOS6 switch where
        the null entry came second and would otherwise have clobbered the
        real name already found for that port. A real name therefore always
        wins over a null placeholder, regardless of which one is seen
        first."""
        neighbors = {}
        current_port = None
        for raw_line in text.splitlines():
            line = raw_line.rstrip('\r')
            m = self.RE_LLDP_PORT.match(line)
            if m:
                current_port = m.group(1)
                continue
            if current_port is None:
                continue
            m = self.RE_SYSTEM_NAME.match(line)
            if m:
                name = m.group(1).strip()
                if name in ("(null)", ""):
                    neighbors.setdefault(current_port, "Not-Advertised")
                else:
                    neighbors[current_port] = name
        return neighbors

    def parse_interfaces_alias(self, text):
        """Port -> (link_state, alias). link_state is normalised to 'A' for
        up, to match the same convention used for Extreme's link state.
        Uses the subclass's RE_ALIAS_LINE for the table's column layout."""
        result = {}
        for raw_line in text.splitlines():
            line = raw_line.rstrip('\r')
            m = self.RE_ALIAS_LINE.match(line)
            if not m:
                continue
            port, _admin_status, link_status, alias = m.groups()
            link = "A" if link_status.lower() == "up" else link_status.upper()
            result[port] = (link, alias)
        return result

    @staticmethod
    def _quote(value):
        return f'"{value}"'

    # -- workflow ------------------------------------------------------

    def scan(self, shell, idle_timeout, overall_timeout, confirm_regex,
              confirm_answer, raw_cb, event_cb, ip):
        event_cb(f"Lese LLDP-Nachbarn ({self.CMD_LLDP})...")
        lldp_out = self._send(shell, self.CMD_LLDP, idle_timeout, overall_timeout,
                               confirm_regex, confirm_answer, raw_cb)
        neighbors = self.parse_lldp_neighbors(lldp_out)

        event_cb(f"Lese Port-Alias/Status ({self.CMD_ALIAS})...")
        alias_out = self._send(shell, self.CMD_ALIAS, idle_timeout, overall_timeout,
                                confirm_regex, confirm_answer, raw_cb)
        port_info = self.parse_interfaces_alias(alias_out)

        rows = []
        for port in sorted(port_info.keys(), key=_port_sort_key):
            link, display = port_info[port]
            neighbor = neighbors.get(port)

            if neighbor == "Not-Advertised":
                action, new_display = "skip", display
                reason = "Not-Advertised (ignoriert)"
            elif link != "A":
                if not display:
                    action, new_display = "none", display
                    reason = "Port inaktiv, aber kein Alias gesetzt"
                elif display.endswith("?"):
                    action, new_display = "none", display
                    reason = "Bereits als inaktiv markiert"
                else:
                    action, new_display = "mark_inactive", display + "?"
                    reason = "Port inaktiv"
            elif neighbor is None:
                action, new_display = "skip", display
                reason = "Kein LLDP-Nachbar erkannt"
            elif neighbor == display:
                action, new_display = "none", display
                reason = "Stimmt bereits mit Neighbor System Name ueberein"
            else:
                action, new_display = "update", neighbor
                reason = "Weicht vom Neighbor System Name ab"

            rows.append(LldpPortRow(
                ip=ip, port=port, link_state=link or "?", neighbor=neighbor or "-",
                current_display=display, new_display=new_display,
                action=action, reason=reason,
                # Alcatel has no Description-String equivalent - leave the
                # column empty rather than inventing a value.
                current_description="",
            ))
        event_cb(f"{len(rows)} Ports ausgewertet", "ok")
        return rows

    def apply(self, shell, idle_timeout, overall_timeout, confirm_regex,
               confirm_answer, raw_cb, event_cb, changes):
        """changes: list of dicts with key "port" and optionally "display"
        (Alcatel has no Description-String field, so a "description" key
        is ignored with a warning rather than sent as an invalid command).
        Returns (applied_count, connection_ok)."""
        applied = 0
        for change in changes:
            port = change["port"]

            if "description" in change:
                event_cb(
                    f"Port {port}: Description-String wird von Alcatel-Lucent "
                    "nicht unterstuetzt, uebersprungen", "warn"
                )

            if "display" in change:
                new_display = change["display"]
                if new_display == "":
                    cmd = f'interfaces {port} alias ""'
                    event_cb(f"Port {port}: loesche Alias")
                else:
                    cmd = f"interfaces {port} alias {self._quote(new_display)}"
                    event_cb(f"Port {port}: setze Alias '{new_display}'")
                out = self._send(shell, cmd, idle_timeout, overall_timeout,
                                  confirm_regex, confirm_answer, raw_cb)
                if "[connection closed by remote host]" in out:
                    event_cb("Verbindung getrennt", "error")
                    return applied, False

            applied += 1

        if applied > 0:
            event_cb(f"Speichere Konfiguration ({self.CMD_SAVE})...")
            self._send(shell, self.CMD_SAVE, idle_timeout, overall_timeout,
                        confirm_regex, confirm_answer, raw_cb)
            event_cb("Konfiguration gespeichert", "ok")
        return applied, True


class AlcatelAOS8VendorHandler(AlcatelBaseVendorHandler):
    """Alcatel-Lucent Enterprise OmniSwitch, AOS8 (e.g. OS6900/OS6860/
    stackable OmniSwitch running the "virtual chassis" AOS8 CLI). Port ids
    are 3-segment "chassis/slot/port" (e.g. "1/1/3")."""

    display_name = "Alcatel-Lucent AOS8"

    CMD_LLDP = "show lldp remote-system"
    CMD_ALIAS = "show interfaces alias"

    # "Remote LLDP nearest-bridge Agents on Local Port 1/1/3:" - one block
    # per detected neighbor, keyed by the local port id. Ports with no
    # neighbor at all simply have no block (unlike Extreme, which lists
    # every port including "Not-Advertised" ones).
    RE_LLDP_PORT = re.compile(r'^Remote LLDP nearest-bridge Agents on Local Port (\S+):\s*$')

    # "show interfaces alias" table row, e.g.:
    #  1/1/1      enable     up      0          0          "Firewall"
    # Port / Admin Status / Link Status / WTR(sec) / WTS(msec) / Alias.
    # The quoted alias makes this unambiguous even when it's empty ("").
    RE_ALIAS_LINE = re.compile(
        r'^\s*(\d+/\d+/\d+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+"(.*)"\s*$'
    )


class AlcatelAOS6VendorHandler(AlcatelBaseVendorHandler):
    """Alcatel-Lucent Enterprise OmniSwitch, AOS6 (e.g. OS6450/OS6350/
    OS6360 fixed switches). Port ids are 2-segment "slot/port" (e.g.
    "1/10"), unlike AOS8's 3-segment "chassis/slot/port"."""

    display_name = "Alcatel-Lucent AOS6"

    CMD_LLDP = "show lldp remote-system"
    CMD_ALIAS = "show interfaces port"

    # "Remote LLDP Agents on Local Slot/Port 1/10:" - same per-port block
    # structure as AOS8, just a slightly different header wording.
    RE_LLDP_PORT = re.compile(r'^Remote LLDP Agents on Local Slot/Port (\S+):\s*$')

    # "show interfaces port" table row, e.g.:
    #   1/10   enable      up        none           300         10          0 "Switch-KG"
    # Slot/Port / Admin Status / Link Status / Violations / Recovery Time /
    # Recovery Max / WTR(sec) / Alias.
    RE_ALIAS_LINE = re.compile(
        r'^\s*(\d+/\d+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+"(.*)"\s*$'
    )


# Two-level vendor abstraction: {vendor display name: {platform display
# name: handler instance or None if not yet implemented}}. Most vendors
# have more than one CLI dialect in the field (Extreme EXOS vs. Fabric
# Engine, Alcatel AOS8 vs. AOS6, ...), so the platform is a separate
# selectable field rather than being folded into the vendor name.
VENDOR_PLATFORMS = {
    "Extreme Networks": {
        "EXOS": ExtremeVendorHandler(),
        "Fabric Engine": None,
    },
    "Alcatel-Lucent": {
        "AOS8": AlcatelAOS8VendorHandler(),
        "AOS6": AlcatelAOS6VendorHandler(),
    },
    "Huawei": {
        "VRP": None,
    },
}

# Selecting this in the Hersteller dropdown skips manual vendor/platform
# selection entirely - each device is identified for itself right after
# login (see detect_vendor_platform), so a single IP list can freely mix
# vendors and OS generations.
AUTO_VENDOR = "Automatisch erkennen"
ALL_VENDOR_NAMES = [AUTO_VENDOR] + list(VENDOR_PLATFORMS.keys())


def detect_vendor_platform(shell, banner, idle_timeout, overall_timeout, confirm_regex,
                            confirm_answer, raw_cb, event_cb):
    """Best-effort auto-detection of a device's vendor/platform from its
    post-login banner and, for Alcatel, a live probe command. Returns
    (handler, label): `handler` is None if the platform isn't implemented
    yet or nothing matched at all; `label` is always a human-readable
    best guess (even when `handler` is None) so the caller can show a
    meaningful message either way.

    - Extreme EXOS (and Fabric Engine, once implemented) print an
      identifying string in their post-login banner/MOTD, which is
      captured for free as part of the normal shell-open sequence -
      no extra command needed.
    - Alcatel AOS6/AOS8 print no real banner - only the bare prompt,
      which (unlike Extreme's "hostname.N # ") ends in "> " with no "#".
      AOS6 and AOS8 use the same "show lldp remote-system" command but
      differ in how the port/alias table is fetched, so that ambiguity
      is resolved with a live probe: AOS8's "show interfaces alias" is
      tried first, and if the switch doesn't understand it (no line
      matches the expected quoted-alias table format) AOS6's "show
      interfaces port" is tried instead. Whichever one actually returns
      a parseable table determines the platform.
    - Huawei VRP's user-view prompt is "<hostname>" (angle brackets) -
      detected only for a clearer "not yet supported" message, since
      Huawei has no implemented handler regardless."""
    text = banner or ""
    lower = text.lower()
    last_line = next((l for l in reversed(text.splitlines()) if l.strip()), "").rstrip()

    if "extremexos" in lower:
        return VENDOR_PLATFORMS["Extreme Networks"]["EXOS"], "Extreme Networks EXOS"
    if "fabric engine" in lower or "voss" in lower:
        return VENDOR_PLATFORMS["Extreme Networks"].get("Fabric Engine"), "Extreme Networks Fabric Engine"

    if last_line.endswith(">") and not last_line.startswith("<"):
        event_cb("Alcatel-Prompt erkannt, ermittle AOS-Version (AOS8-Testabfrage)...")
        aos8 = VENDOR_PLATFORMS["Alcatel-Lucent"]["AOS8"]
        probe8 = aos8._send(shell, aos8.CMD_ALIAS, idle_timeout, overall_timeout,
                             confirm_regex, confirm_answer, raw_cb)
        if aos8.parse_interfaces_alias(probe8):
            return aos8, "Alcatel-Lucent AOS8"
        event_cb("Keine AOS8-Tabelle erkannt, versuche AOS6 (show interfaces port)...")
        aos6 = VENDOR_PLATFORMS["Alcatel-Lucent"]["AOS6"]
        probe6 = aos6._send(shell, aos6.CMD_ALIAS, idle_timeout, overall_timeout,
                             confirm_regex, confirm_answer, raw_cb)
        if aos6.parse_interfaces_alias(probe6):
            return aos6, "Alcatel-Lucent AOS6"
        return None, "Alcatel-Lucent (AOS-Version unklar)"

    if last_line.startswith("<") and last_line.endswith(">"):
        return VENDOR_PLATFORMS["Huawei"].get("VRP"), "Huawei VRP"

    return None, None


def lldp_scan_device(ip, port, username, password, vendor_handler, idle_timeout,
                      overall_timeout, confirm_regex, confirm_answer, event_cb,
                      stop_event, username2=None, password2=None):
    """Read-only LLDP scan of a single device. If username2 is set, it is
    tried as a fallback login when (username, password) is rejected. If
    vendor_handler is None, the vendor/platform is auto-detected for this
    device right after login (see detect_vendor_platform), so a single IP
    list can mix vendors/generations - the resolved handler is returned so
    the caller can reuse the exact same one later for Apply without
    detecting again.
    Returns (status_string, rows, full_log_string, handler_or_None)."""
    log_lines = [f"=== LLDP-Scan {ip}:{port} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n"]

    def raw(text):
        log_lines.append(text)

    def event(msg, level="info"):
        log_lines.append(f"\n[{level.upper()}] {msg}\n")
        if event_cb:
            event_cb(msg, level)

    if not PARAMIKO_AVAILABLE:
        event("paramiko ist nicht installiert", "error")
        return "Error: paramiko missing", [], "".join(log_lines), None

    if stop_event.is_set():
        event("Uebersprungen (gestoppt)", "warn")
        return "Stopped", [], "".join(log_lines), None

    client = None
    try:
        client, shell, banner = open_ssh_shell(ip, port, username, password, idle_timeout,
                                                overall_timeout, confirm_regex, confirm_answer,
                                                raw, event, username2, password2)

        handler = vendor_handler
        if handler is None:
            event("Erkenne Hersteller/Plattform...")
            handler, label = detect_vendor_platform(
                shell, banner, idle_timeout, overall_timeout, confirm_regex,
                confirm_answer, raw, event,
            )
            if handler is None:
                suffix = f" ({label})" if label else ""
                event(f"Hersteller/Plattform nicht erkannt oder nicht unterstuetzt{suffix}", "error")
                return (f"Error: Hersteller nicht erkannt/unterstuetzt{suffix}", [],
                        "".join(log_lines), None)
            event(f"Erkannt: {label}", "ok")

        rows = handler.scan(shell, idle_timeout, overall_timeout, confirm_regex,
                              confirm_answer, raw, event, ip)
        return "OK", rows, "".join(log_lines), handler
    except paramiko.AuthenticationException:
        event("Authentifizierung fehlgeschlagen", "error")
        return "Error: auth failed", [], "".join(log_lines), None
    except Exception as e:
        event(f"Fehler: {e}", "error")
        return f"Error: {e}", [], "".join(log_lines), None
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def lldp_apply_device(ip, port, username, password, vendor_handler, changes,
                       idle_timeout, overall_timeout, confirm_regex, confirm_answer,
                       event_cb, stop_event, username2=None, password2=None):
    """Applies a list of change dicts to a single device and saves the
    config if anything was applied. If username2 is set, it is tried as a
    fallback login when (username, password) is rejected.
    Returns (status_string, applied_count, full_log_string)."""
    log_lines = [f"=== LLDP-Apply {ip}:{port} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n"]

    def raw(text):
        log_lines.append(text)

    def event(msg, level="info"):
        log_lines.append(f"\n[{level.upper()}] {msg}\n")
        if event_cb:
            event_cb(msg, level)

    if not PARAMIKO_AVAILABLE:
        event("paramiko ist nicht installiert", "error")
        return "Error: paramiko missing", 0, "".join(log_lines)

    if stop_event.is_set():
        event("Uebersprungen (gestoppt)", "warn")
        return "Stopped", 0, "".join(log_lines)

    client = None
    try:
        client, shell, _banner = open_ssh_shell(ip, port, username, password, idle_timeout,
                                                 overall_timeout, confirm_regex, confirm_answer,
                                                 raw, event, username2, password2)
        applied, ok = vendor_handler.apply(shell, idle_timeout, overall_timeout,
                                             confirm_regex, confirm_answer, raw, event,
                                             changes)
        if not ok:
            return f"Error: Verbindung getrennt ({applied} von {len(changes)} gesetzt)", applied, "".join(log_lines)
        event(f"{applied} Port(s) aktualisiert", "ok")
        return "OK", applied, "".join(log_lines)
    except paramiko.AuthenticationException:
        event("Authentifizierung fehlgeschlagen", "error")
        return "Error: auth failed", 0, "".join(log_lines)
    except Exception as e:
        event(f"Fehler: {e}", "error")
        return f"Error: {e}", 0, "".join(log_lines)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# IP parsing helpers
# ---------------------------------------------------------------------------

def parse_ip_range(start_ip, end_ip):
    start = int(ipaddress.IPv4Address(start_ip.strip()))
    end = int(ipaddress.IPv4Address(end_ip.strip()))
    if end < start:
        start, end = end, start
    return [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]


def parse_ip_list(text):
    ips = [p.strip() for p in text.split(",")]
    ips = [p for p in ips if p]
    for ip in ips:
        ipaddress.IPv4Address(ip)  # validation, raises ValueError if bad
    return ips


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

ACTION_LABELS = {
    "update": "Update Display-String",
    "mark_inactive": "Inaktiv -> '?' anhaengen",
    "skip": "Ignoriert",
    "none": "Keine Aenderung",
    "delete": "Display-String loeschen",
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"SSH Command & LLDP Tool v{APP_VERSION}")
        self.geometry("1080x820")
        self.minsize(920, 680)

        self.gui_queue = queue.Queue()

        # --- Commands tab state ---
        self.cmd_stop_event = threading.Event()
        self.cmd_worker_thread = None
        self.results = {}  # ip -> DeviceResult
        self.row_for_ip = {}  # ip -> treeview item id
        self._done_devices = 0
        self._total_devices = 0

        # --- LLDP-Update tab state ---
        self.lldp_stop_event = threading.Event()
        self.lldp_worker_thread = None
        self.lldp_rows = {}       # (ip, port) -> LldpPortRow
        self.lldp_row_item = {}   # (ip, port) -> treeview item id
        self.lldp_device_logs = {}  # ip -> combined raw log text
        self.lldp_handlers_by_ip = {}  # ip -> vendor handler resolved during scan
                                        # (manually selected, or auto-detected per
                                        # device); Apply reuses this instead of
                                        # re-detecting so it always matches Scan.
        self._lldp_scan_done = 0
        self._lldp_scan_total = 0
        self._lldp_apply_done = 0
        self._lldp_apply_total = 0
        self._lldp_edit_entry = None

        self._build_ui()
        self._load_saved_config()
        self.protocol("WM_DELETE_WINDOW", self._on_close_window)
        self.after(100, self._poll_queue)

        if not PARAMIKO_AVAILABLE:
            self._log_cmd_line(
                "[WARNUNG] Das Modul 'paramiko' wurde nicht gefunden. "
                "Bitte installieren mit: pip install paramiko", "error"
            )

    # ---------------- UI construction ----------------

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        # --- Device IP Addresses (shared) ---
        ip_frame = ttk.LabelFrame(self, text="Device IP Addresses")
        ip_frame.pack(fill="x", **pad)

        self.ip_mode = tk.StringVar(value="list")
        ttk.Radiobutton(ip_frame, text="IP Range", variable=self.ip_mode,
                         value="range").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Radiobutton(ip_frame, text="IP List (comma separated)",
                         variable=self.ip_mode, value="list").grid(
            row=0, column=1, sticky="w", padx=6, pady=4)

        ttk.Label(ip_frame, text="Start IP:").grid(row=1, column=0, sticky="e", padx=6)
        self.start_ip_var = tk.StringVar()
        ttk.Entry(ip_frame, textvariable=self.start_ip_var, width=18).grid(
            row=1, column=1, sticky="w", padx=6)

        ttk.Label(ip_frame, text="End IP:").grid(row=1, column=2, sticky="e", padx=6)
        self.end_ip_var = tk.StringVar()
        ttk.Entry(ip_frame, textvariable=self.end_ip_var, width=18).grid(
            row=1, column=3, sticky="w", padx=6)

        ttk.Label(ip_frame, text="IP List:").grid(row=2, column=0, sticky="e", padx=6)
        self.ip_list_var = tk.StringVar()
        ttk.Entry(ip_frame, textvariable=self.ip_list_var).grid(
            row=2, column=1, columnspan=3, sticky="ew", padx=6, pady=4)
        ip_frame.columnconfigure(3, weight=1)

        # --- SSH Login (shared) ---
        login_frame = ttk.LabelFrame(self, text="SSH Login")
        login_frame.pack(fill="x", **pad)

        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.username_var = tk.StringVar(value="admin")
        ttk.Entry(login_frame, textvariable=self.username_var, width=16).grid(
            row=0, column=1, sticky="w", padx=6)

        ttk.Label(login_frame, text="Password:").grid(row=0, column=2, sticky="e", padx=6)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(login_frame, textvariable=self.password_var,
                                         width=16, show="*")
        self.password_entry.grid(row=0, column=3, sticky="w", padx=6)

        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(login_frame, text="show", variable=self.show_pw_var,
                         command=self._toggle_password).grid(row=0, column=4, sticky="w")

        ttk.Label(login_frame, text="Fallback Username:").grid(
            row=1, column=0, sticky="e", padx=6, pady=4)
        self.username2_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.username2_var, width=16).grid(
            row=1, column=1, sticky="w", padx=6)

        ttk.Label(login_frame, text="Fallback Password:").grid(row=1, column=2, sticky="e", padx=6)
        self.password2_var = tk.StringVar()
        self.password2_entry = ttk.Entry(login_frame, textvariable=self.password2_var,
                                          width=16, show="*")
        self.password2_entry.grid(row=1, column=3, sticky="w", padx=6)

        self.show_pw2_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(login_frame, text="show", variable=self.show_pw2_var,
                         command=self._toggle_password2).grid(row=1, column=4, sticky="w")
        ttk.Label(
            login_frame,
            text="wird nur versucht, wenn Username/Password oben abgelehnt werden",
            foreground="#999999",
        ).grid(row=1, column=5, columnspan=4, sticky="w", padx=6)

        ttk.Label(login_frame, text="Port:").grid(row=2, column=0, sticky="e", padx=6, pady=4)
        self.port_var = tk.StringVar(value="22")
        ttk.Entry(login_frame, textvariable=self.port_var, width=5).grid(
            row=2, column=1, sticky="w", padx=6)

        ttk.Label(login_frame, text="Parallel sessions:").grid(row=2, column=2, sticky="e", padx=6)
        self.parallel_var = tk.StringVar(value="5")
        ttk.Entry(login_frame, textvariable=self.parallel_var, width=5).grid(
            row=2, column=3, sticky="w", padx=6)

        self.remember_password_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(login_frame, text="Passwort merken",
                         variable=self.remember_password_var).grid(
            row=3, column=0, columnspan=3, sticky="w", padx=6, pady=(0, 4))
        ttk.Label(
            login_frame,
            text="IP-Adressen, Username(s), Port, Parallel-Sessions, Commands to Send und "
                 "(falls aktiviert) die Passwoerter werden lokal verschluesselt gespeichert "
                 "und beim naechsten Start automatisch geladen.",
            foreground="#999999",
        ).grid(row=3, column=3, columnspan=6, sticky="w", padx=6, pady=(0, 4))

        # --- Notebook: LLDP-Update  |  Commands to Send ---
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        tab_lldp = ttk.Frame(self.notebook)
        tab_cmd = ttk.Frame(self.notebook)
        
        self.notebook.add(tab_cmd, text="Commands to Send")
        self.notebook.add(tab_lldp, text="LLDP-Update")

        self._build_lldp_tab(tab_lldp)
        self._build_commands_tab(tab_cmd)

        # --- Footer ---
        footer = ttk.Frame(self)
        footer.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(
            footer, text=f"v{APP_VERSION}  © {APP_AUTHOR}", foreground="#999999"
        ).pack(side="right", padx=(4, 16))

    def _toggle_password(self):
        self.password_entry.configure(show="" if self.show_pw_var.get() else "*")

    def _toggle_password2(self):
        self.password2_entry.configure(show="" if self.show_pw2_var.get() else "*")

    # ---------------- persisted settings (IP addresses + SSH login) ----------------

    def _load_saved_config(self):
        try:
            cfg = load_config()
        except Exception:
            cfg = {}
        if not cfg:
            return
        self.ip_mode.set(cfg.get("ip_mode", self.ip_mode.get()))
        self.start_ip_var.set(cfg.get("start_ip", ""))
        self.end_ip_var.set(cfg.get("end_ip", ""))
        self.ip_list_var.set(cfg.get("ip_list", ""))
        self.username_var.set(cfg.get("username", self.username_var.get()))
        self.username2_var.set(cfg.get("username2", ""))
        self.port_var.set(cfg.get("port", self.port_var.get()))
        self.parallel_var.set(cfg.get("parallel", self.parallel_var.get()))
        self.remember_password_var.set(cfg.get("remember_password", True))
        if self.remember_password_var.get():
            self.password_var.set(cfg.get("password", ""))
            self.password2_var.set(cfg.get("password2", ""))
        if "commands" in cfg:
            self.commands_text.delete("1.0", "end")
            self.commands_text.insert("1.0", cfg.get("commands") or DEFAULT_COMMANDS)

    def _save_current_config(self):
        remember_password = self.remember_password_var.get()
        values = {
            "ip_mode": self.ip_mode.get(),
            "start_ip": self.start_ip_var.get(),
            "end_ip": self.end_ip_var.get(),
            "ip_list": self.ip_list_var.get(),
            "username": self.username_var.get(),
            "username2": self.username2_var.get(),
            "port": self.port_var.get(),
            "parallel": self.parallel_var.get(),
            "remember_password": remember_password,
            "password": self.password_var.get() if remember_password else "",
            "password2": self.password2_var.get() if remember_password else "",
            "commands": self.commands_text.get("1.0", "end-1c"),
        }
        try:
            save_config(values)
        except Exception:
            pass

    def _on_close_window(self):
        self._save_current_config()
        self.destroy()

    def _get_target_ips(self):
        if self.ip_mode.get() == "range":
            return parse_ip_range(self.start_ip_var.get(), self.end_ip_var.get())
        return parse_ip_list(self.ip_list_var.get())

    def _get_login_params(self):
        """Reads/validates the shared IP + SSH Login fields. Raises
        ValueError with a user-facing message on invalid input. The
        fallback username/password are optional - username2 is "" if not
        configured, in which case callers skip the fallback login."""
        try:
            ips = self._get_target_ips()
        except Exception as e:
            raise ValueError(f"Konnte IP-Adressen nicht lesen:\n{e}")
        if not ips:
            raise ValueError("Bitte mindestens eine IP-Adresse angeben.")

        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not username:
            raise ValueError("Bitte Username angeben.")

        username2 = self.username2_var.get().strip()
        password2 = self.password2_var.get()

        try:
            port = int(self.port_var.get())
        except ValueError:
            raise ValueError("Port muss eine Zahl sein.")

        try:
            max_parallel = max(1, int(self.parallel_var.get()))
        except ValueError:
            raise ValueError("Parallel sessions muss eine Zahl sein.")

        return ips, port, username, password, max_parallel, username2, password2

    # =========================================================================
    # LLDP-Update tab
    # =========================================================================

    def _build_lldp_tab(self, parent):
        pad = {"padx": 8, "pady": 6}

        top = ttk.Frame(parent)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Hersteller:").pack(side="left")
        # Default to auto-detection - each device identifies itself right
        # after login, so a single IP list can freely mix vendors and OS
        # generations. Picking a specific vendor here overrides that for
        # the whole batch (see _on_lldp_vendor_selected / _on_lldp_scan).
        self.vendor_var = tk.StringVar(value=AUTO_VENDOR)
        vendor_combo = ttk.Combobox(top, textvariable=self.vendor_var, values=ALL_VENDOR_NAMES,
                                     state="readonly", width=20)
        vendor_combo.pack(side="left", padx=(4, 12))
        vendor_combo.bind("<<ComboboxSelected>>", self._on_lldp_vendor_selected)

        ttk.Label(top, text="Plattform:").pack(side="left")
        self.platform_var = tk.StringVar(value="-")
        self.platform_combo = ttk.Combobox(top, textvariable=self.platform_var, values=["-"],
                                            state="disabled", width=14)
        self.platform_combo.pack(side="left", padx=(4, 16))

        ttk.Label(top, text="Idle timeout (s):").pack(side="left")
        self.lldp_idle_timeout_var = tk.StringVar(value="5")
        ttk.Entry(top, textvariable=self.lldp_idle_timeout_var, width=5).pack(
            side="left", padx=(2, 12))

        ttk.Label(top, text="Per-cmd max wait (s):").pack(side="left")
        self.lldp_overall_timeout_var = tk.StringVar(value="30")
        ttk.Entry(top, textvariable=self.lldp_overall_timeout_var, width=5).pack(
            side="left", padx=(2, 12))

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill="x", padx=8)

        self.lldp_scan_btn = ttk.Button(btn_row, text="Scan", command=self._on_lldp_scan)
        self.lldp_scan_btn.pack(side="left", padx=4)
        self.lldp_stop_btn = ttk.Button(btn_row, text="Stop", command=self._on_lldp_stop,
                                          state="disabled")
        self.lldp_stop_btn.pack(side="left", padx=4)
        self.lldp_select_pending_btn = ttk.Button(
            btn_row, text="Alle offenen auswaehlen", command=self._on_lldp_select_pending,
            state="disabled")
        self.lldp_select_pending_btn.pack(side="left", padx=4)
        self.lldp_delete_btn = ttk.Button(
            btn_row, text="Display-String loeschen", command=self._on_lldp_mark_delete,
            state="disabled")
        self.lldp_delete_btn.pack(side="left", padx=4)
        self.lldp_apply_btn = ttk.Button(btn_row, text="Apply Changes",
                                           command=self._on_lldp_apply, state="disabled")
        self.lldp_apply_btn.pack(side="left", padx=4)

        self.lldp_status_var = tk.StringVar(value="Ready")
        ttk.Label(btn_row, textvariable=self.lldp_status_var).pack(side="left", padx=12)

        ttk.Button(btn_row, text="Export", command=self._on_lldp_export).pack(side="right", padx=4)
        ttk.Button(btn_row, text="Clear", command=self._on_lldp_clear).pack(side="right", padx=4)
        ttk.Button(btn_row, text="Change-Log oeffnen",
                   command=self._on_lldp_open_change_log).pack(side="right", padx=4)

        # --- Preview table ---
        table_frame = ttk.LabelFrame(
            parent, text="Ports  (Zeilen auswaehlen und 'Apply Changes' klicken, um nur die "
                         "ausgewaehlten Aenderungen zu senden. Klick auf 'Neuer Display-String' "
                         "oder 'Neuer Description-String' = Wert manuell bearbeiten.)")
        table_frame.pack(fill="both", expand=True, padx=8, pady=6)

        columns = ("ip", "port", "link", "neighbor", "current", "new",
                   "current_desc", "new_desc", "action", "reason", "result")
        self.lldp_tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                       height=10, selectmode="extended")
        headings = {
            "ip": ("IP Address", 120), "port": ("Port", 50), "link": ("Link", 45),
            "neighbor": ("Neighbor System Name", 150), "current": ("Aktueller Display-String", 140),
            "new": ("Neuer Display-String", 140),
            "current_desc": ("Aktueller Description-String", 160),
            "new_desc": ("Neuer Description-String", 160),
            "action": ("Aktion", 150), "reason": ("Grund", 200), "result": ("Status", 80),
        }
        for col, (text, width) in headings.items():
            self.lldp_tree.heading(col, text=text)
            self.lldp_tree.column(col, width=width, anchor="w")
        self.lldp_tree.pack(fill="both", expand=True, side="left")

        lldp_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.lldp_tree.yview)
        lldp_scroll.pack(side="right", fill="y")
        self.lldp_tree.configure(yscrollcommand=lldp_scroll.set)

        self.lldp_tree.tag_configure("upd", foreground="#0066cc")
        self.lldp_tree.tag_configure("inact", foreground="#cc7a00")
        self.lldp_tree.tag_configure("skip", foreground="#999999")
        self.lldp_tree.tag_configure("none", foreground="#555555")
        self.lldp_tree.tag_configure("del", foreground="#aa0044")
        self.lldp_tree.tag_configure("applied", foreground="#1a7a1a")
        self.lldp_tree.tag_configure("apply_error", foreground="#b30000")

        self.lldp_tree.bind("<Double-1>", self._on_lldp_row_double_click)
        self.lldp_tree.bind("<Button-1>", self._on_lldp_tree_click)

        # --- LLDP Log ---
        log_frame = ttk.LabelFrame(parent, text="LLDP Log")
        log_frame.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.lldp_log_text = scrolledtext.ScrolledText(log_frame, height=7, state="disabled")
        self.lldp_log_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.lldp_log_text.tag_configure("info", foreground="black")
        self.lldp_log_text.tag_configure("ok", foreground="#1a7a1a")
        self.lldp_log_text.tag_configure("error", foreground="#b30000")
        self.lldp_log_text.tag_configure("warn", foreground="#cc7a00")

    # ---------------- inline editing of "Neuer Display-String" / "Neuer Description-String" ----------------

    LLDP_TREE_COLUMNS = ("ip", "port", "link", "neighbor", "current", "new",
                         "current_desc", "new_desc", "action", "reason", "result")
    LLDP_EDITABLE_COLUMNS = {"new": "display", "new_desc": "description"}

    def _lldp_row_to_values(self, row):
        return (row.ip, row.port, row.link_state, row.neighbor, row.current_display,
                row.new_display, row.current_description, row.new_description,
                ACTION_LABELS.get(row.action, row.action), row.reason, row.result)

    def _lldp_row_tag(self, row):
        if row.action in ("update", "mark_inactive", "delete"):
            return {"update": "upd", "mark_inactive": "inact", "delete": "del"}[row.action]
        # "none"/"skip" display action but a pending, independent
        # description edit should still stand out visually.
        if row.has_description_change():
            return "upd"
        return "skip" if row.action == "skip" else "none"

    def _refresh_lldp_row(self, item, row):
        self.lldp_tree.item(item, values=self._lldp_row_to_values(row),
                              tags=(self._lldp_row_tag(row),))
        has_pending = any(r.is_actionable() for r in self.lldp_rows.values())
        self.lldp_apply_btn.configure(state="normal" if has_pending else "disabled")

    def _on_lldp_tree_click(self, event):
        region = self.lldp_tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        column = self.lldp_tree.identify_column(event.x)  # e.g. "#6"
        item = self.lldp_tree.identify_row(event.y)
        if not item:
            return
        try:
            col_index = int(column.replace("#", "")) - 1
        except ValueError:
            return
        if col_index < 0 or col_index >= len(self.LLDP_TREE_COLUMNS):
            return
        field = self.LLDP_EDITABLE_COLUMNS.get(self.LLDP_TREE_COLUMNS[col_index])
        if field is None:
            return  # only "Neuer Display-String" / "Neuer Description-String" are editable

        values = self.lldp_tree.item(item, "values")
        ip, port_num = values[0], values[1]
        row = self.lldp_rows.get((ip, port_num))
        if row is None:
            return
        self._start_lldp_inline_edit(item, column, row, field)

    def _start_lldp_inline_edit(self, item, column, row, field):
        if self._lldp_edit_entry is not None:
            self._lldp_edit_entry.destroy()
            self._lldp_edit_entry = None

        bbox = self.lldp_tree.bbox(item, column)
        if not bbox:
            return
        x, y, width, height = bbox

        current_value = row.new_display if field == "display" else row.new_description
        var = tk.StringVar(value=current_value)
        entry = ttk.Entry(self.lldp_tree, textvariable=var)
        entry.place(x=x, y=y, width=width, height=height)
        entry.focus_set()
        entry.select_range(0, "end")
        self._lldp_edit_entry = entry

        def commit(_event=None):
            if self._lldp_edit_entry is None:
                return
            new_value = var.get()
            entry.destroy()
            self._lldp_edit_entry = None
            if field == "display":
                self._apply_manual_display_edit(row, item, new_value)
            else:
                self._apply_manual_description_edit(row, item, new_value)

        def cancel(_event=None):
            if self._lldp_edit_entry is None:
                return
            entry.destroy()
            self._lldp_edit_entry = None

        entry.bind("<Return>", commit)
        entry.bind("<KP_Enter>", commit)
        entry.bind("<FocusOut>", commit)
        entry.bind("<Escape>", cancel)

    def _apply_manual_display_edit(self, row, item, new_value):
        """Applies a manually typed value from the inline editor on
        'Neuer Display-String': empty clears the display string (like the
        'Display-String loeschen' button), a value equal to the current
        one means no change, anything else is a manual update - all made
        actionable for 'Apply Changes'."""
        if new_value == row.current_display:
            row.action = "none"
            row.new_display = row.current_display
            row.reason = "Manuell bestaetigt (keine Aenderung)"
        elif new_value == "":
            row.action = "delete"
            row.new_display = ""
            row.reason = "Manuell zum Loeschen markiert"
        else:
            row.action = "update"
            row.new_display = new_value
            row.reason = "Manuell bearbeitet"
        row.result = ""
        row._orig_action = None
        row._orig_new_display = None
        row._orig_reason = None
        self._refresh_lldp_row(item, row)

    def _apply_manual_description_edit(self, row, item, new_value):
        """Applies a manually typed value from the inline editor on
        'Neuer Description-String'. Independent of the Display-String
        action - a row can have a pending description change even if its
        display action is 'Keine Aenderung'."""
        row.new_description = new_value
        row.result = ""
        self._refresh_lldp_row(item, row)

    def _on_lldp_row_double_click(self, _event):
        sel = self.lldp_tree.selection()
        if not sel:
            return
        values = self.lldp_tree.item(sel[0], "values")
        ip = values[0]
        log_text = self.lldp_device_logs.get(ip)
        if not log_text:
            return
        self._show_log_window(ip, log_text)

    def _on_lldp_clear(self):
        if self._lldp_edit_entry is not None:
            self._lldp_edit_entry.destroy()
            self._lldp_edit_entry = None
        for item in self.lldp_tree.get_children():
            self.lldp_tree.delete(item)
        self.lldp_rows = {}
        self.lldp_row_item = {}
        self.lldp_device_logs = {}
        self.lldp_handlers_by_ip = {}
        self.lldp_log_text.configure(state="normal")
        self.lldp_log_text.delete("1.0", "end")
        self.lldp_log_text.configure(state="disabled")
        self.lldp_apply_btn.configure(state="disabled")
        self.lldp_select_pending_btn.configure(state="disabled")
        self.lldp_delete_btn.configure(state="disabled")
        self.lldp_status_var.set("Ready")

    def _on_lldp_select_pending(self):
        pending = [item for item, row in self._lldp_tree_rows() if row.is_actionable()]
        self.lldp_tree.selection_set(pending)

    def _lldp_tree_rows(self):
        for (ip, port), item in self.lldp_row_item.items():
            row = self.lldp_rows.get((ip, port))
            if row is not None:
                yield item, row

    def _on_lldp_mark_delete(self):
        """Toggles the currently selected row(s): if a row is not yet
        marked for deletion, mark it so 'Apply Changes' clears
        (unconfigures) its display string - stashing whatever the scan
        originally proposed. If the row is already marked, clicking again
        restores that original scan result instead."""
        selected = self.lldp_tree.selection()
        if not selected:
            messagebox.showinfo(
                "Display-String loeschen",
                "Bitte zuerst eine oder mehrere Zeilen in der Tabelle auswaehlen.",
            )
            return

        marked = 0
        unmarked = 0
        for item in selected:
            values = self.lldp_tree.item(item, "values")
            ip, port_num = values[0], values[1]
            row = self.lldp_rows.get((ip, port_num))
            if row is None:
                continue

            if row.action == "delete":
                # Toggle off: restore what the scan originally determined.
                row.action = row._orig_action if row._orig_action is not None else "none"
                row.new_display = (row._orig_new_display if row._orig_new_display is not None
                                    else row.current_display)
                row.reason = row._orig_reason if row._orig_reason is not None else ""
                row._orig_action = None
                row._orig_new_display = None
                row._orig_reason = None
                row.result = ""
                unmarked += 1
            else:
                row._orig_action = row.action
                row._orig_new_display = row.new_display
                row._orig_reason = row.reason
                row.action = "delete"
                row.new_display = ""
                row.reason = "Manuell zum Loeschen markiert"
                row.result = ""
                marked += 1

            self.lldp_tree.item(item, values=self._lldp_row_to_values(row),
                                  tags=(self._lldp_row_tag(row),))

        if marked or unmarked:
            parts = []
            if marked:
                parts.append(f"{marked} Port(s) zum Loeschen markiert")
            if unmarked:
                parts.append(f"{unmarked} Port(s) zurueckgesetzt")
            self._log_lldp_line(", ".join(parts) + ".")
            has_pending = any(row.is_actionable() for row in self.lldp_rows.values())
            self.lldp_apply_btn.configure(state="normal" if has_pending else "disabled")

    def _on_lldp_vendor_selected(self, event=None):
        vendor = self.vendor_var.get()
        if vendor == AUTO_VENDOR:
            self.platform_combo.configure(values=["-"], state="disabled")
            self.platform_var.set("-")
            return
        platforms = list(VENDOR_PLATFORMS.get(vendor, {}).keys())
        self.platform_combo.configure(values=platforms, state="readonly")
        if platforms:
            self.platform_var.set(platforms[0])

    def _on_lldp_scan(self):
        if not PARAMIKO_AVAILABLE:
            messagebox.showerror(
                "Missing dependency",
                "Das Modul 'paramiko' ist nicht installiert.\n\nBitte ausfuehren: pip install paramiko",
            )
            return

        vendor = self.vendor_var.get()
        if vendor == AUTO_VENDOR:
            # None signals "auto-detect per device" all the way down to
            # lldp_scan_device - each device identifies itself right after
            # login, so the IP list can freely mix vendors/generations.
            handler = None
        else:
            platform = self.platform_var.get()
            handler = VENDOR_PLATFORMS.get(vendor, {}).get(platform)
            if handler is None:
                implemented = [
                    f"{v} {p}" for v, plats in VENDOR_PLATFORMS.items()
                    for p, h in plats.items() if h is not None
                ]
                messagebox.showinfo(
                    "Plattform noch nicht unterstuetzt",
                    f"'{vendor} {platform}' wird aktuell noch nicht unterstuetzt.\n\n"
                    "Aktuell implementiert: " + ", ".join(implemented),
                )
                return

        try:
            ips, port, username, password, max_parallel, username2, password2 = self._get_login_params()
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))
            return

        try:
            idle_timeout = float(self.lldp_idle_timeout_var.get())
            overall_timeout = float(self.lldp_overall_timeout_var.get())
        except ValueError:
            messagebox.showerror("Invalid timeout", "Timeout-Werte muessen Zahlen sein.")
            return

        self._on_lldp_clear()
        confirm_regex = re.compile(DEFAULT_CONFIRM_PATTERN, re.IGNORECASE)

        self.lldp_stop_event = threading.Event()
        self._lldp_scan_done = 0
        self._lldp_scan_total = len(ips)
        self.lldp_scan_btn.configure(state="disabled")
        self.lldp_stop_btn.configure(state="normal")
        self.lldp_apply_btn.configure(state="disabled")
        self.lldp_status_var.set(f"Scanning... (0/{len(ips)})")

        self.lldp_worker_thread = threading.Thread(
            target=self._run_lldp_scan_batch,
            args=(ips, port, username, password, handler, idle_timeout, overall_timeout,
                  confirm_regex, "y", max_parallel, username2, password2),
            daemon=True,
        )
        self.lldp_worker_thread.start()

    def _lldp_scan_one(self, ip, port, username, password, handler, idle_timeout,
                        overall_timeout, confirm_regex, confirm_answer, username2, password2):
        def event_cb(msg, level):
            self.gui_queue.put(("lldp_scan_event", ip, msg, level))

        status, rows, full_log, resolved_handler = lldp_scan_device(
            ip, port, username, password, handler, idle_timeout, overall_timeout,
            confirm_regex, confirm_answer, event_cb, self.lldp_stop_event,
            username2, password2,
        )
        self.gui_queue.put(("lldp_scan_done", ip, status, rows, full_log, resolved_handler))

    def _run_lldp_scan_batch(self, ips, port, username, password, handler, idle_timeout,
                              overall_timeout, confirm_regex, confirm_answer, max_parallel,
                              username2, password2):
        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            futures = [
                executor.submit(self._lldp_scan_one, ip, port, username, password, handler,
                                 idle_timeout, overall_timeout, confirm_regex, confirm_answer,
                                 username2, password2)
                for ip in ips
            ]
            for _ in as_completed(futures):
                pass
        self.gui_queue.put(("lldp_scan_batch_done",))

    def _on_lldp_stop(self):
        self.lldp_stop_event.set()
        self.lldp_status_var.set("Stopping...")

    def _on_lldp_apply(self):
        selected = self.lldp_tree.selection()
        if not selected:
            messagebox.showinfo(
                "Apply Changes",
                "Bitte zu uebernehmende Zeilen auswaehlen "
                "(oder 'Alle offenen auswaehlen' klicken).",
            )
            return

        changes_by_ip = {}
        display_count = 0
        description_count = 0
        for item in selected:
            values = self.lldp_tree.item(item, "values")
            ip, port_num = values[0], values[1]
            row = self.lldp_rows.get((ip, port_num))
            if row is None:
                continue
            change = {}
            if row.action in ("mark_inactive", "update", "delete"):
                change["display"] = row.new_display
                display_count += 1
            if row.has_description_change():
                change["description"] = row.new_description
                description_count += 1
            if not change:
                continue
            change["port"] = port_num
            changes_by_ip.setdefault(ip, []).append(change)

        if not changes_by_ip:
            messagebox.showinfo(
                "Apply Changes",
                "Keine offenen Aenderungen in der Auswahl (nur Zeilen mit Display-String-"
                "Aktion 'Update'/'Inaktiv'/'Loeschen' oder einem bearbeiteten Description-"
                "String koennen uebernommen werden).",
            )
            return

        # Each device keeps the handler resolved for it during Scan (either
        # manually selected or auto-detected) - Apply reuses that directly
        # instead of detecting again, so mixed-vendor batches always use
        # the same handler per device that was used to scan it.
        handlers_by_ip = {ip: self.lldp_handlers_by_ip.get(ip) for ip in changes_by_ip}
        missing = [ip for ip, h in handlers_by_ip.items() if h is None]
        if missing:
            messagebox.showerror(
                "Apply Changes",
                "Fuer folgende Geraet(e) liegt kein erfolgreicher Scan (mit erkanntem/"
                "ausgewaehltem Hersteller) vor, bitte zuerst erneut scannen:\n\n"
                + ", ".join(missing),
            )
            return

        total_ports = sum(len(v) for v in changes_by_ip.values())
        if not messagebox.askyesno(
            "Apply Changes bestaetigen",
            f"{total_ports} Port(s) auf {len(changes_by_ip)} Geraet(en) werden geaendert "
            f"({display_count} Display-String, {description_count} Description-String) "
            f"und die Konfiguration wird automatisch gespeichert (save).\n\nFortfahren?",
        ):
            return

        try:
            _, port, username, password, max_parallel, username2, password2 = self._get_login_params()
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))
            return

        try:
            idle_timeout = float(self.lldp_idle_timeout_var.get())
            overall_timeout = float(self.lldp_overall_timeout_var.get())
        except ValueError:
            messagebox.showerror("Invalid timeout", "Timeout-Werte muessen Zahlen sein.")
            return

        confirm_regex = re.compile(DEFAULT_CONFIRM_PATTERN, re.IGNORECASE)
        self.lldp_stop_event = threading.Event()
        self._lldp_apply_done = 0
        self._lldp_apply_total = len(changes_by_ip)
        self.lldp_scan_btn.configure(state="disabled")
        self.lldp_apply_btn.configure(state="disabled")
        self.lldp_select_pending_btn.configure(state="disabled")
        self.lldp_stop_btn.configure(state="normal")
        self.lldp_status_var.set(f"Applying... (0/{len(changes_by_ip)})")

        self.lldp_worker_thread = threading.Thread(
            target=self._run_lldp_apply_batch,
            args=(changes_by_ip, port, username, password, handlers_by_ip, idle_timeout,
                  overall_timeout, confirm_regex, "y", max_parallel, username2, password2),
            daemon=True,
        )
        self.lldp_worker_thread.start()

    def _lldp_apply_one(self, ip, changes, port, username, password, handler, idle_timeout,
                         overall_timeout, confirm_regex, confirm_answer, username2, password2):
        def event_cb(msg, level):
            self.gui_queue.put(("lldp_apply_event", ip, msg, level))

        status, applied, full_log = lldp_apply_device(
            ip, port, username, password, handler, changes, idle_timeout, overall_timeout,
            confirm_regex, confirm_answer, event_cb, self.lldp_stop_event,
            username2, password2,
        )
        self.gui_queue.put(("lldp_apply_done", ip, changes, status, applied, full_log))

    def _run_lldp_apply_batch(self, changes_by_ip, port, username, password, handlers_by_ip,
                               idle_timeout, overall_timeout, confirm_regex, confirm_answer,
                               max_parallel, username2, password2):
        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            futures = [
                executor.submit(self._lldp_apply_one, ip, changes, port, username, password,
                                 handlers_by_ip[ip], idle_timeout, overall_timeout, confirm_regex,
                                 confirm_answer, username2, password2)
                for ip, changes in changes_by_ip.items()
            ]
            for _ in as_completed(futures):
                pass
        self.gui_queue.put(("lldp_apply_batch_done",))

    def _on_lldp_export(self):
        if not self.lldp_rows:
            messagebox.showinfo("Export", "Keine LLDP-Ergebnisse vorhanden.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=f"lldp_update_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Port", "Link", "Neighbor System Name",
                              "Aktueller Display-String", "Neuer Display-String",
                              "Aktueller Description-String", "Neuer Description-String",
                              "Aktion", "Grund", "Status"])
            for (ip, p), row in sorted(self.lldp_rows.items(), key=lambda kv: (kv[0][0], _port_sort_key(kv[0][1]))):
                writer.writerow([ip, p, row.link_state, row.neighbor, row.current_display,
                                  row.new_display, row.current_description, row.new_description,
                                  ACTION_LABELS.get(row.action, row.action),
                                  row.reason, row.result])
        self._log_lldp_line(f"LLDP-Ergebnisse exportiert nach: {path}")

    def _on_lldp_open_change_log(self):
        if not os.path.exists(CHANGE_LOG_FILE):
            messagebox.showinfo(
                "Change-Log",
                "Es wurden bisher noch keine Aenderungen protokolliert.\n\n"
                f"Pfad (wird beim ersten Apply automatisch angelegt):\n{CHANGE_LOG_FILE}",
            )
            return
        try:
            os.startfile(CHANGE_LOG_FILE)
        except Exception:
            messagebox.showinfo("Change-Log", f"Log-Datei:\n{CHANGE_LOG_FILE}")

    def _log_lldp_line(self, text, level="info"):
        self.lldp_log_text.configure(state="normal")
        self.lldp_log_text.insert("end", text + "\n", level)
        self.lldp_log_text.see("end")
        self.lldp_log_text.configure(state="disabled")

    def _insert_lldp_placeholder_row(self, ip, message):
        """Used when a scan succeeds but yields zero parsed ports, so the
        device still shows up in the table and its raw transcript remains
        reachable via double-click (which only needs column 0 = ip)."""
        self.lldp_tree.insert("", "end", values=(
            ip, "-", "-", "-", "-", "-", "-", "-", "-", message, "",
        ), tags=("skip",))

    def _insert_lldp_row(self, row):
        item = self.lldp_tree.insert("", "end", values=self._lldp_row_to_values(row),
                                       tags=(self._lldp_row_tag(row),))
        self.lldp_row_item[(row.ip, row.port)] = item
        self.lldp_rows[(row.ip, row.port)] = row

    def _update_lldp_row_result(self, ip, port, result, ok):
        row = self.lldp_rows.get((ip, port))
        item = self.lldp_row_item.get((ip, port))
        if row is None or item is None:
            return
        row.result = result
        if ok:
            # The requested value is now what's actually configured on the
            # device, so "current" catches up with "new" for both fields.
            row.current_display = row.new_display
            row.current_description = row.new_description
        self.lldp_tree.item(item, values=self._lldp_row_to_values(row),
                              tags=("applied" if ok else "apply_error",))

    # =========================================================================
    # Commands to Send tab
    # =========================================================================

    def _build_commands_tab(self, parent):
        pad = {"padx": 8, "pady": 6}

        cmd_frame = ttk.LabelFrame(parent, text="Commands to Send (one per line, in order)")
        cmd_frame.pack(fill="x", **pad)

        self.commands_text = tk.Text(cmd_frame, height=4, wrap="none")
        self.commands_text.insert("1.0", DEFAULT_COMMANDS)
        self.commands_text.pack(fill="x", padx=6, pady=(6, 2))

        opts_frame = ttk.Frame(cmd_frame)
        opts_frame.pack(fill="x", padx=6, pady=(0, 6))

        self.auto_confirm_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts_frame, text="Auto-confirm (Y/N) prompts with:",
                         variable=self.auto_confirm_var).pack(side="left")
        self.confirm_answer_var = tk.StringVar(value="y")
        ttk.Entry(opts_frame, textvariable=self.confirm_answer_var, width=4).pack(
            side="left", padx=(2, 12))

        ttk.Label(opts_frame, text="Idle timeout (s):").pack(side="left")
        self.idle_timeout_var = tk.StringVar(value="5")
        ttk.Entry(opts_frame, textvariable=self.idle_timeout_var, width=5).pack(
            side="left", padx=(2, 12))

        ttk.Label(opts_frame, text="Per-cmd max wait (s):").pack(side="left")
        self.overall_timeout_var = tk.StringVar(value="30")
        ttk.Entry(opts_frame, textvariable=self.overall_timeout_var, width=5).pack(
            side="left", padx=(2, 12))

        # --- Command Results ---
        results_frame = ttk.LabelFrame(parent, text="Command Results  (double-click a row to view its log)")
        results_frame.pack(fill="both", expand=True, **pad)

        columns = ("ip", "status", "commands", "time")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=8)
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("status", text="Status")
        self.tree.heading("commands", text="Commands Sent")
        self.tree.heading("time", text="Last Update")
        self.tree.column("ip", width=140, anchor="w")
        self.tree.column("status", width=300, anchor="w")
        self.tree.column("commands", width=120, anchor="center")
        self.tree.column("time", width=120, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=6, pady=6, side="left")

        tree_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.tag_configure("ok", foreground="#1a7a1a")
        self.tree.tag_configure("error", foreground="#b30000")
        self.tree.tag_configure("warn", foreground="#cc7a00")
        self.tree.tag_configure("running", foreground="#0066cc")

        self.tree.bind("<Double-1>", self._on_row_double_click)

        # --- Running Log ---
        log_frame = ttk.LabelFrame(parent, text="Running Log")
        log_frame.pack(fill="both", expand=True, **pad)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_text.tag_configure("info", foreground="black")
        self.log_text.tag_configure("ok", foreground="#1a7a1a")
        self.log_text.tag_configure("error", foreground="#b30000")
        self.log_text.tag_configure("warn", foreground="#cc7a00")

        # --- Bottom bar ---
        bottom = ttk.Frame(parent)
        bottom.pack(fill="x", padx=8, pady=(0, 8))

        self.cmd_start_btn = ttk.Button(bottom, text="Start", command=self._on_start)
        self.cmd_start_btn.pack(side="left", padx=4)
        self.cmd_stop_btn = ttk.Button(bottom, text="Stop", command=self._on_stop, state="disabled")
        self.cmd_stop_btn.pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left", padx=12)

        ttk.Button(bottom, text="Export Results", command=self._on_export).pack(side="right", padx=4)
        ttk.Button(bottom, text="Clear Log", command=self._on_clear_log).pack(side="right", padx=4)

    # ---------------- actions ----------------

    def _on_clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _on_row_double_click(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        ip = self.tree.item(item, "values")[0]
        result = self.results.get(ip)
        if not result:
            return
        self._show_log_window(ip, result.log)

    def _show_log_window(self, ip, log_text):
        win = tk.Toplevel(self)
        win.title(f"Log - {ip}")
        win.geometry("700x500")

        txt = scrolledtext.ScrolledText(win, wrap="word")
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("1.0", log_text if log_text else "(no log captured)")
        txt.configure(state="disabled")

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", padx=8, pady=(0, 8))

        def save_log():
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                initialfile=f"{ip}_log.txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            )
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(log_text)

        ttk.Button(btn_frame, text="Save to file...", command=save_log).pack(side="right")
        ttk.Button(btn_frame, text="Close", command=win.destroy).pack(side="right", padx=6)

    def _get_commands(self):
        raw = self.commands_text.get("1.0", "end")
        return [line for line in raw.splitlines() if line.strip()]

    def _on_start(self):
        if not PARAMIKO_AVAILABLE:
            messagebox.showerror(
                "Missing dependency",
                "Das Modul 'paramiko' ist nicht installiert.\n\n"
                "Bitte ausfuehren: pip install paramiko",
            )
            return

        try:
            ips, port, username, password, max_parallel, username2, password2 = self._get_login_params()
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))
            return

        commands = self._get_commands()
        if not commands:
            messagebox.showerror("No commands", "Bitte mindestens einen Befehl angeben.")
            return

        try:
            idle_timeout = float(self.idle_timeout_var.get())
            overall_timeout = float(self.overall_timeout_var.get())
        except ValueError:
            messagebox.showerror("Invalid timeout", "Timeout-Werte muessen Zahlen sein.")
            return

        auto_confirm = self.auto_confirm_var.get()
        confirm_answer = self.confirm_answer_var.get() or "y"
        confirm_regex = re.compile(DEFAULT_CONFIRM_PATTERN, re.IGNORECASE)

        # Reset table/state for a new run
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results = {}
        self.row_for_ip = {}
        self._done_devices = 0
        self._total_devices = len(ips)

        for ip in ips:
            result = DeviceResult(ip)
            self.results[ip] = result
            item = self.tree.insert("", "end", values=(ip, "Pending", "0/" + str(len(commands)), ""))
            self.row_for_ip[ip] = item
            self.tree.item(item, tags=("running",))

        self.cmd_stop_event = threading.Event()
        self.cmd_start_btn.configure(state="disabled")
        self.cmd_stop_btn.configure(state="normal")
        self.status_var.set(f"Running... (0/{len(ips)})")

        self.cmd_worker_thread = threading.Thread(
            target=self._run_batch,
            args=(ips, port, username, password, commands, idle_timeout,
                  overall_timeout, auto_confirm, confirm_regex, confirm_answer,
                  max_parallel, username2, password2),
            daemon=True,
        )
        self.cmd_worker_thread.start()

    def _on_stop(self):
        self.cmd_stop_event.set()
        self.status_var.set("Stopping...")

    def _on_export(self):
        if not self.results:
            messagebox.showinfo("Export Results", "Keine Ergebnisse vorhanden.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"ssh_command_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        if path.lower().endswith(".csv"):
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "Status", "Commands Sent"])
                for ip, result in self.results.items():
                    writer.writerow([ip, result.status, result.commands_sent])
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write("SSH Command Tool - Results Export\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")
                for ip, result in self.results.items():
                    f.write(f"IP: {ip}\nStatus: {result.status}\n")
                    f.write("-" * 70 + "\n")
                    f.write(result.log)
                    f.write("\n\n" + "=" * 70 + "\n\n")
        self._log_cmd_line(f"Results exported to: {path}")

    # ---------------- worker threads ----------------

    def _run_one(self, ip, port, username, password, commands, idle_timeout,
                 overall_timeout, auto_confirm, confirm_regex, confirm_answer,
                 username2, password2):
        """Runs in a thread-pool worker thread - one call per device."""
        if self.cmd_stop_event.is_set():
            self.gui_queue.put(("device_event", ip, "Uebersprungen (gestoppt)", "warn"))
            self.gui_queue.put(("device_done", ip, "Stopped", "", 0))
            return

        def event_cb(msg, level):
            self.gui_queue.put(("device_event", ip, msg, level))

        status, full_log, commands_sent = run_device(
            ip, port, username, password, commands,
            idle_timeout, overall_timeout, auto_confirm,
            confirm_regex, confirm_answer, event_cb, self.cmd_stop_event,
            username2, password2,
        )
        self.gui_queue.put(("device_done", ip, status, full_log, commands_sent))

    def _run_batch(self, ips, port, username, password, commands, idle_timeout,
                    overall_timeout, auto_confirm, confirm_regex, confirm_answer,
                    max_parallel, username2, password2):
        """Coordinator thread: dispatches all devices to a bounded thread
        pool so up to `max_parallel` SSH sessions run at the same time."""
        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            futures = [
                executor.submit(
                    self._run_one, ip, port, username, password, commands,
                    idle_timeout, overall_timeout, auto_confirm, confirm_regex,
                    confirm_answer, username2, password2,
                )
                for ip in ips
            ]
            for _ in as_completed(futures):
                pass
        self.gui_queue.put(("batch_done",))

    # ---------------- GUI queue handling (runs on main thread) ----------------

    def _poll_queue(self):
        try:
            while True:
                item = self.gui_queue.get_nowait()
                kind = item[0]

                # --- Commands tab events ---
                if kind == "device_event":
                    _, ip, msg, level = item
                    ts = datetime.now().strftime("%H:%M:%S")
                    self._log_cmd_line(f"{ts}  {ip:<15} {msg}", level)
                    self._update_row(ip, status=msg)
                elif kind == "device_done":
                    _, ip, status, full_log, commands_sent = item
                    result = self.results.get(ip)
                    if result is not None:
                        result.status = status
                        result.log = full_log
                        result.commands_sent = commands_sent
                    ts = datetime.now().strftime("%H:%M:%S")
                    level = "ok" if status.startswith("OK") else (
                        "warn" if status == "Stopped" else "error")
                    self._log_cmd_line(f"{ts}  {ip:<15} Status: {status}", level)
                    self._update_row(ip, status=status, timestamp=ts, final=True)
                    self._done_devices += 1
                    self.status_var.set(f"Running... ({self._done_devices}/{self._total_devices})")
                elif kind == "batch_done":
                    self.cmd_start_btn.configure(state="normal")
                    self.cmd_stop_btn.configure(state="disabled")
                    self.status_var.set("Ready")

                # --- LLDP-Update tab events ---
                elif kind == "lldp_scan_event":
                    _, ip, msg, level = item
                    ts = datetime.now().strftime("%H:%M:%S")
                    self._log_lldp_line(f"{ts}  {ip:<15} {msg}", level)
                elif kind == "lldp_scan_done":
                    _, ip, status, rows, full_log, resolved_handler = item
                    self.lldp_device_logs[ip] = full_log
                    if resolved_handler is not None:
                        self.lldp_handlers_by_ip[ip] = resolved_handler
                    else:
                        self.lldp_handlers_by_ip.pop(ip, None)
                    ts = datetime.now().strftime("%H:%M:%S")
                    level = "ok" if status == "OK" else ("warn" if status == "Stopped" else "error")
                    vendor_suffix = f" [{resolved_handler.display_name}]" if resolved_handler is not None else ""
                    self._log_lldp_line(
                        f"{ts}  {ip:<15} Scan: {status} ({len(rows)} Ports){vendor_suffix}", level)
                    if rows:
                        for row in rows:
                            self._insert_lldp_row(row)
                    elif status == "OK":
                        self._insert_lldp_placeholder_row(
                            ip, "Keine Ports erkannt - Doppelklick zeigt Rohlog")
                    self._lldp_scan_done += 1
                    self.lldp_status_var.set(f"Scanning... ({self._lldp_scan_done}/{self._lldp_scan_total})")
                elif kind == "lldp_scan_batch_done":
                    self.lldp_scan_btn.configure(state="normal")
                    self.lldp_stop_btn.configure(state="disabled")
                    has_pending = any(row.is_actionable() for row in self.lldp_rows.values())
                    self.lldp_apply_btn.configure(state="normal" if has_pending else "disabled")
                    self.lldp_select_pending_btn.configure(state="normal" if has_pending else "disabled")
                    self.lldp_delete_btn.configure(state="normal" if self.lldp_rows else "disabled")
                    self.lldp_status_var.set("Ready" if has_pending else "Ready (keine offenen Aenderungen)")
                elif kind == "lldp_apply_event":
                    _, ip, msg, level = item
                    ts = datetime.now().strftime("%H:%M:%S")
                    self._log_lldp_line(f"{ts}  {ip:<15} {msg}", level)
                elif kind == "lldp_apply_done":
                    _, ip, changes, status, applied, full_log = item
                    self.lldp_device_logs[ip] = self.lldp_device_logs.get(ip, "") + "\n" + full_log
                    ts = datetime.now().strftime("%H:%M:%S")
                    ok = status == "OK"
                    level = "ok" if ok else ("warn" if status == "Stopped" else "error")
                    self._log_lldp_line(
                        f"{ts}  {ip:<15} Apply: {status} ({applied}/{len(changes)} Port(s) gesetzt)", level)
                    log_entries = []
                    for i, change in enumerate(changes):
                        port_num = change["port"]
                        port_ok = ok and i < applied
                        row = self.lldp_rows.get((ip, port_num))
                        old_display = row.current_display if row is not None else ""
                        old_description = row.current_description if row is not None else ""
                        action_label = ACTION_LABELS.get(row.action, row.action) if row is not None else ""
                        status = "Applied" if port_ok else "Error"
                        self._update_lldp_row_result(ip, port_num, status, port_ok)
                        entry_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        if "display" in change:
                            log_entries.append({
                                "timestamp": entry_ts, "ip": ip, "port": port_num,
                                "field": "Display-String", "old": old_display,
                                "new": change["display"], "action": action_label, "status": status,
                            })
                        if "description" in change:
                            log_entries.append({
                                "timestamp": entry_ts, "ip": ip, "port": port_num,
                                "field": "Description-String", "old": old_description,
                                "new": change["description"], "action": action_label, "status": status,
                            })
                    try:
                        append_lldp_change_log(log_entries)
                    except Exception:
                        pass
                    self._lldp_apply_done += 1
                    self.lldp_status_var.set(f"Applying... ({self._lldp_apply_done}/{self._lldp_apply_total})")
                elif kind == "lldp_apply_batch_done":
                    self.lldp_scan_btn.configure(state="normal")
                    self.lldp_stop_btn.configure(state="disabled")
                    self.lldp_select_pending_btn.configure(state="normal")
                    self.lldp_delete_btn.configure(state="normal" if self.lldp_rows else "disabled")
                    has_pending = any(row.is_actionable() and row.result != "Applied"
                                       for row in self.lldp_rows.values())
                    self.lldp_apply_btn.configure(state="normal" if has_pending else "disabled")
                    self.lldp_status_var.set("Ready")

        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _update_row(self, ip, status=None, timestamp=None, final=False):
        item = self.row_for_ip.get(ip)
        if not item:
            return
        values = list(self.tree.item(item, "values"))
        if status is not None:
            values[1] = status
        if timestamp is not None:
            values[3] = timestamp
        result = self.results.get(ip)
        if result is not None:
            commands = self._get_commands()
            if commands:
                values[2] = f"{result.commands_sent}/{len(commands)}"
        self.tree.item(item, values=values)

        if final:
            if status and status.startswith("OK"):
                tag = ("ok",)
            elif status == "Stopped":
                tag = ("warn",)
            elif status and status.startswith("Error"):
                tag = ("error",)
            else:
                tag = ()
        else:
            tag = ("running",)
        self.tree.item(item, tags=tag)

    def _log_cmd_line(self, text, level="info"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")


if __name__ == "__main__":
    app = App()
    app.mainloop()
