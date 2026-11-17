import sys
import os
import re
import json
import time
import signal
import getpass
import subprocess
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

PROXY_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROXY_DIR, "config.json")
TOKEN_FILE = os.path.join(PROXY_DIR, ".vault_token")
PID_FILE = os.path.join(PROXY_DIR, "proxy.pid")
LOG_FILE = os.path.join(PROXY_DIR, "proxy.log")
SERVER_PY = os.path.join(PROXY_DIR, "server.py")


def load_cli_config() -> Dict[str, Any]:
    cfg = {"host": "127.0.0.1", "port": 8765, "secrets_file": "secrets.json"}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


cli_cfg = load_cli_config()
HOST = str(cli_cfg.get("host", "127.0.0.1"))
PORT = int(cli_cfg.get("port", 8765))
BASE_URL = f"http://{HOST}:{PORT}"
SECRETS_FILE = os.path.join(PROXY_DIR, str(cli_cfg.get("secrets_file", "secrets.json")))

# ANSI Colors
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def get_auth_headers() -> Dict[str, str]:
    """Retrieves CLI headers including authentication token from .vault_token or config.json."""
    headers = {"User-Agent": "ZVault-CLI"}
    token = None

    # Check .vault_token first
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                t = f.read().strip()
                if t:
                    token = t
        except Exception:
            pass

    # Check config.json if not found
    if not token and os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                token = cfg.get("vault_token")
        except Exception:
            pass

    if token:
        headers["X-Vault-Token"] = token
    return headers


def is_running() -> bool:
    """Checks if the proxy server is responding on its port."""
    try:
        req = urllib.request.Request(f"{BASE_URL}/", headers={"User-Agent": "ZVault-CLI"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_pid() -> Optional[int]:
    """Reads PID from pid file if valid and running."""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())

            if sys.platform == "win32":
                check = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"],
                    capture_output=True, text=True
                )
                if str(pid) in check.stdout:
                    return pid
            else:
                try:
                    os.kill(pid, 0)
                    return pid
                except OSError:
                    pass
        except Exception:
            pass
    return None


def cmd_start(args):
    """Starts the proxy in background or foreground."""
    foreground = "-f" in args or "--foreground" in args

    if is_running():
        pid = get_pid()
        pid_str = f" (PID: {pid})" if pid else ""
        print(f"{YELLOW}ZVault is already running{RESET} on {GREEN}{BASE_URL}{RESET}{pid_str}")
        return

    python_exe = sys.executable

    if foreground:
        print(f"{CYAN}{BOLD}Starting ZVault in foreground...{RESET}")
        try:
            subprocess.run([python_exe, SERVER_PY], cwd=PROXY_DIR)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}ZVault stopped.{RESET}")
    else:
        print(f"Starting {CYAN}{BOLD}ZVault{RESET} on {GREEN}{BASE_URL}{RESET}...", end=" ", flush=True)

        if sys.platform == "win32":
            creationflags = 0x00000010  # CREATE_NEW_CONSOLE
            proc = subprocess.Popen(
                [python_exe, SERVER_PY],
                cwd=PROXY_DIR,
                creationflags=creationflags
            )
            bg_pid = str(proc.pid)
            with open(PID_FILE, "w") as f:
                f.write(bg_pid)
        else:
            proc = subprocess.Popen(
                [python_exe, SERVER_PY],
                cwd=PROXY_DIR,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            with open(PID_FILE, "w") as f:
                f.write(str(proc.pid))

        started = False
        for _ in range(16):
            time.sleep(0.25)
            if is_running():
                started = True
                break

        if started:
            pid = get_pid()
            pid_label = f" (PID: {pid})" if pid else ""
            print(f"{GREEN}{BOLD}✓ OK{RESET}{pid_label}")
            print(f"Logs: {CYAN}{LOG_FILE}{RESET}")
        else:
            print(f"{RED}{BOLD}✗ Failed to start.{RESET}")
            print(f"Check log file for errors: {LOG_FILE}")


def cmd_stop():
    """Stops the running proxy."""
    pid = get_pid()
    stopped = False

    if pid:
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
            else:
                os.kill(pid, signal.SIGTERM)
            stopped = True
        except Exception:
            pass

    # If PID file was stale or missing, find process listening strictly on :PORT (listening sockets only!)
    if not stopped or is_running():
        try:
            if sys.platform == "win32":
                netstat = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
                port_regex = re.compile(rf":{PORT}\s")
                for line in netstat.stdout.splitlines():
                    if port_regex.search(line) and "LISTENING" in line:
                        parts = line.strip().split()
                        port_pid = parts[-1]
                        subprocess.run(["taskkill", "/F", "/PID", port_pid], capture_output=True)
                        stopped = True
            else:
                # -sTCP:LISTEN strictly matches listening server processes, not client sockets (e.g. IDE)
                lsof = subprocess.run(["lsof", "-t", "-sTCP:LISTEN", f"-i:{PORT}"], capture_output=True, text=True)
                for p in lsof.stdout.strip().splitlines():
                    if p:
                        os.kill(int(p), signal.SIGKILL)
                        stopped = True
        except Exception:
            pass

    for _ in range(12):
        if not is_running():
            break
        time.sleep(0.25)

    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except Exception:
            pass

    if is_running():
        print(f"{RED}Failed to stop ZVault on port {PORT}.{RESET}")
    else:
        print(f"{GREEN}{BOLD}✓ ZVault stopped.{RESET}")


def cmd_status():
    """Displays running status, secret counts and loaded env files."""
    if is_running():
        pid = get_pid()
        pid_str = f" [PID {pid}]" if pid else ""
        print(f"\n{GREEN}{BOLD}● ZVault is RUNNING{RESET}{pid_str} on {CYAN}{BASE_URL}{RESET}")

        try:
            req = urllib.request.Request(f"{BASE_URL}/vault/status", headers=get_auth_headers())
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                print(f"  Total secrets in vault: {GREEN}{data.get('count', 0)}{RESET}")
                print(f"  Active .env files:")
                for ef in data.get("env_files", []):
                    print(f"    - {ef}")
        except Exception as e:
            print(f"  (Failed to query details: {e})")

        try:
            req = urllib.request.Request(f"{BASE_URL}/", headers={"User-Agent": "ZVault-CLI"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                print(f"  Upstreams configured: {YELLOW}{', '.join(data.get('upstreams', []))}{RESET}")
        except Exception:
            pass
        print()
    else:
        print(f"\n{RED}○ ZVault is STOPPED{RESET} (Port {PORT} is idle)\n")


def cmd_add(path_arg: str):
    """Adds a .env file path to the vault and configuration."""
    abs_path = os.path.abspath(path_arg)

    if not os.path.exists(abs_path):
        print(f"{RED}Error:{RESET} File not found: {abs_path}")
        return

    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)

    env_list = config.setdefault("env_files", [])
    if abs_path not in env_list:
        env_list.append(abs_path)
        tmp_cfg = f"{CONFIG_FILE}.tmp_{os.getpid()}_{time.time_ns()}"
        with open(tmp_cfg, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        if hasattr(os, "chmod") and sys.platform != "win32":
            try:
                os.chmod(tmp_cfg, 0o600)
            except Exception:
                pass
        os.replace(tmp_cfg, CONFIG_FILE)

    if is_running():
        try:
            headers = get_auth_headers()
            headers["Content-Type"] = "application/json"
            req = urllib.request.Request(
                f"{BASE_URL}/vault/add-env",
                data=json.dumps({"path": abs_path}).encode("utf-8"),
                headers=headers
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                loaded = res_data.get("loaded_secrets", 0)
                total = res_data.get("total_vault_secrets", 0)
                print(f"{GREEN}{BOLD}✓ Added and loaded live!{RESET} (+{loaded} secrets from .env, total in vault: {total})")
                print(f"  Path: {CYAN}{abs_path}{RESET}")
                return
        except Exception as e:
            print(f"{YELLOW}Added to config, but failed live reload:{RESET} {e}")
            return

    print(f"{GREEN}{BOLD}✓ Saved to config.json{RESET} (will load on next start)")
    print(f"  Path: {CYAN}{abs_path}{RESET}")


def cmd_str(secret: str, label: Optional[str] = None):
    """
    Adds a custom sensitive string to the vault with collision & duplicate handling.
    """
    if not secret:
        print(f"{RED}Error:{RESET} Secret string cannot be empty.")
        return

    if is_running():
        try:
            headers = get_auth_headers()
            headers["Content-Type"] = "application/json"
            req = urllib.request.Request(
                f"{BASE_URL}/vault/add-secret",
                data=json.dumps({"secret": secret, "label": label or "STR"}).encode("utf-8"),
                headers=headers
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                placeholder = data.get("placeholder")
                existed = data.get("already_existed", False)
                total = data.get("total_vault_secrets", 0)

                if existed:
                    print(f"{YELLOW}Secret already registered!{RESET} Reusing placeholder: {GREEN}{BOLD}{placeholder}{RESET}")
                else:
                    print(f"{GREEN}{BOLD}✓ Secret added and active live!{RESET}")
                    print(f"  Placeholder: {GREEN}{BOLD}{placeholder}{RESET} (Total in vault: {total})")
                return
        except Exception as e:
            print(f"{YELLOW}Warning: live update failed ({e}), saving to secrets.json...{RESET}")

    secrets_path = SECRETS_FILE
    stored = {}
    if os.path.exists(secrets_path):
        try:
            with open(secrets_path, "r", encoding="utf-8") as f:
                stored = json.load(f)
        except Exception:
            stored = {}

    for ph, sec in stored.items():
        if sec == secret:
            print(f"{YELLOW}Secret already registered!{RESET} Reusing placeholder: {GREEN}{BOLD}{ph}{RESET}")
            return

    clean_label = (label or "STR").upper()
    next_idx = 1
    while True:
        new_ph = f"__VAULT_{clean_label}_{next_idx:02d}__"
        if new_ph not in stored:
            break
        next_idx += 1

    stored[new_ph] = secret

    tmp_sec = f"{secrets_path}.tmp_{os.getpid()}_{time.time_ns()}"
    with open(tmp_sec, "w", encoding="utf-8") as f:
        json.dump(stored, f, indent=2, ensure_ascii=False)
    if hasattr(os, "chmod") and sys.platform != "win32":
        try:
            os.chmod(tmp_sec, 0o600)
        except Exception:
            pass
    os.replace(tmp_sec, secrets_path)

    print(f"{GREEN}{BOLD}✓ Saved to secrets.json{RESET} (will load on next start)")
    print(f"  Placeholder: {GREEN}{BOLD}{new_ph}{RESET}")


def cmd_logs():
    """Prints recent lines from proxy.log."""
    if not os.path.exists(LOG_FILE):
        print("No log file found.")
        return
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
        tail = lines[-40:] if len(lines) > 40 else lines
        print("".join(tail))


def print_help():
    print(f"""
{CYAN}{BOLD}ZVault CLI{RESET} - Secret Masking Gateway for ZCode

{BOLD}Usage:{RESET}
  zv start [-f]              Start proxy (background by default, or -f for foreground)
  zv stop                    Stop proxy
  zv restart                 Restart proxy
  zv status                  Show status, active secrets count, and loaded .env files
  zv add <path>              Add a .env file (e.g. `zv add ./.env` or `zv add C:/path/.env`)
  zv str ["<secret>"] ["TAG"] Add an ad-hoc secret string (prompts securely if omitted)
  zv logs                    View recent background logs
  zv help                    Show this help message

{BOLD}CLI Name:{RESET}
  Use {GREEN}{BOLD}zv{RESET} or {GREEN}{BOLD}zvault{RESET} interchangeably!
""")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("help", "-h", "--help"):
        print_help()
        return

    command = args[0].lower()

    if command == "start":
        cmd_start(args[1:])
    elif command == "stop":
        cmd_stop()
    elif command == "restart":
        cmd_stop()
        time.sleep(0.5)
        cmd_start(args[1:])
    elif command == "status":
        cmd_status()
    elif command == "add":
        if len(args) < 2:
            print(f"{RED}Usage:{RESET} zv add <path-to-.env>")
            return
        cmd_add(args[1])
    elif command in ("str", "secret"):
        if len(args) < 2:
            try:
                secret_val = getpass.getpass("Enter secret string (input hidden): ").strip()
            except Exception:
                secret_val = input("Enter secret string: ").strip()
            label_val = input("Optional label (or press Enter for default): ").strip() or None
        else:
            secret_val = args[1]
            label_val = args[2] if len(args) > 2 else None
        cmd_str(secret_val, label_val)
    elif command == "logs":
        cmd_logs()
    else:
        print(f"{RED}Unknown command:{RESET} {command}")
        print_help()


if __name__ == "__main__":
    main()
