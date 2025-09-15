# 🐝 HoneyPot

A minimal **combined honeypot** that runs two traps:

- **Web honeypot** — a Flask-based fake login portal that captures web-based attack attempts.
- **SSH honeypot** — a simple SSH service emulator that logs connection attempts and credentials.

This project is intended for **education and research**: studying attacker behaviour, logging unauthorized access attempts, and experimenting with detection techniques.

---


## Requirements

- Python 3.8+
- `pip` to install dependencies

Install required packages from `requirements.txt`.

---

## Installation

```bash
git clone https://github.com/hman-deep/HoneyPot.git
cd HoneyPot
python3 -m venv venv
source venv/bin/activate   # macOS / Linux
# venv\\Scripts\\activate  # Windows
pip install -r requirements.txt
```

---

## Usage

To provision a new instance of HONEYPY, use the `honeypy.py` file. This is the main file to interface with for HONEYPY. 

HONEYPY requires a bind IP address (`-a`) and network port to listen on (`-p`). Use `0.0.0.0` to listen on all network interfaces. The protocol type must also be defined.

```
-a / --address: Bind address.
-p / --port: Port.
-s / --ssh OR -wh / --http: Declare honeypot type.
```

Example: `python3 honeypy.py -a 0.0.0.0 -p 22 --ssh`

**Optional Arguments**

A username (`-u`) and password (`-w`) can be specified to authenticate the SSH server. The default configuration will accept all usernames and passwords.

```
-u / --username: Username.
-w / --password: Password.
-t / --tarpit: For SSH-based honeypots, -t can be used to trap sessions inside the shell, by sending a 'endless' SSH banner.
```

Example: `python3 main.py -a 0.0.0.0 -p 22 --ssh -u admin -p admin --tarpit`


## Logs

HONEYPY has three loggers configured. Loggers will route to either `cmd_audits.log`, `creds_audits.log` (for SSH), and `http_audit.log` (for HTTP) log files for information capture.

`cmd_audits.log`: Captures IP address, username, password, and all commands supplied.

`creds_audits.log`: Captures IP address, username, and password, comma seperated. Used to see how many hosts attempt to connect to SSH_HONEYPY.

`http_audit.log`: Captures IP address, username, password.
