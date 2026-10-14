# SSH Command & LLDP Tool

A local Python desktop tool that **runs CLI commands on multiple switches via SSH**
and **checks and updates port descriptions based on LLDP neighbors** – for
Alcatel-Lucent Enterprise AOS6, AOS8 and Extreme Networks EXOS.

No Python is needed on the switch: the tool runs on your computer and talks to
the existing CLI over SSH.

![Version](https://img.shields.io/badge/version-1.1.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Background article: [SSH Command & LLDP Tool](https://www.dominikgawin.de/en/ssh-command-lldp-tool/)
(German version: [dominikgawin.de](https://www.dominikgawin.de/))

## Features

### SSH commands on multiple switches
- IP list or IP range as target
- Any number of CLI commands, executed per device
- Parallel sessions (configurable, default: 5)
- Credentials plus alternative credentials as fallback
- Output logged per device, export as text or CSV

### LLDP-based port descriptions
- Automatic platform detection (mixed device lists are possible)
- Reads LLDP neighbors and existing port descriptions / aliases and compares them
- Generates change proposals – **a scan alone never changes the configuration**
- Proposals can be selected, edited or marked for removal before applying
- Changes are only sent after confirmation, then the configuration is saved
- Change log in CSV format for every applied change

Comparison rules:

| Situation | Behaviour |
|---|---|
| Description matches the LLDP neighbor | no change |
| LLDP name differs | update is proposed |
| Neighbor reports `Not-Advertised` | entry is ignored |
| No LLDP neighbor on the port | existing description is **not** deleted |
| Port inactive | an appended `?` can be proposed as a hint |

## Supported platforms

| Platform | SSH commands | LLDP descriptions |
|---|---|---|
| Alcatel-Lucent Enterprise AOS6 | ✔ | ✔ |
| Alcatel-Lucent Enterprise AOS8 | ✔ | ✔ |
| Extreme Networks EXOS | ✔ | ✔ (names are shortened to the EXOS field length) |
| Fabric Engine, Huawei VRP | – | not implemented yet |

## Requirements

- Python 3.8+ with Tkinter (Windows is the primary platform; the UI is partly in German)
- SSH access to the switches
- LLDP enabled on the relevant ports

```bash
python -m pip install -r requirements.txt
```

`paramiko` is pinned below 3.3 on purpose: newer releases dropped legacy `ssh-rsa`
support that older switches (e.g. Extreme x440) still need. `pyinstaller` is only
needed to build a standalone executable.

## Usage

```bash
python ssh_lldp_descriptor.py
```

1. Enter the IP addresses or an IP range
2. Set the credentials
3. **SSH tab:** check the command list, then run it
4. **LLDP tab:** start a scan, review the proposals, select the entries you want and apply them

> **Check the command list before you start.** Y/N confirmation prompts
> (e.g. for `reboot`) are answered automatically when *Auto-confirm* is enabled.

## Build a standalone executable

On Windows, run `build_exe.bat`. It installs the requirements and builds
`dist\SSH_Command_LLDP_Tool.exe`, which runs on other PCs without Python.

## Security notes

- Settings are stored in `%APPDATA%\SSHLLDPTool\` (`config.json`, change log `lldp_change_log.csv`).
- Stored passwords are protected with DPAPI on Windows and Fernet encryption on other platforms.
- Unknown SSH host keys are currently **accepted automatically**. Use the tool only in trusted management networks.
- Legacy SSH algorithms (`ssh-rsa`, `ssh-dss`, SHA-1 key exchange, CBC ciphers) are always offered as a
  low-priority fallback so older switches can connect. Modern devices still negotiate stronger algorithms.
- Logs and exports may contain IP addresses and device names – the `.gitignore` keeps them out of Git.

## Related project

[ALE-LLDP-Alias](https://github.com/dgawin/ALE-LLDP-Alias) – the predecessor that runs
directly on an AOS8 OmniSwitch.

## Changelog

### v1.1.0 (2026-07-02)
- LLDP-Update tab for ALE AOS6, AOS8 and Extreme EXOS with automatic platform detection
- Change proposals with manual editing and clearing, CSV change log
- Fallback credentials, encrypted password storage
- Legacy SSH algorithm support for older switches

### v1.0.0 (2026-06-19)
- SSH Command Tool: run command lists on multiple devices in parallel

## Disclaimer

This is a personal project and is not affiliated with Alcatel-Lucent Enterprise,
Extreme Networks or my employer SPIE. Use at your own risk – always review command
lists and change proposals before applying them.

## License

MIT – see [LICENSE](LICENSE).
