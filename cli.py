import sys
import os
import json
import time
import subprocess
import urllib.request
import urllib.error

PROXY_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROXY_DIR, "config.json")
PID_FILE = os.path.join(PROXY_DIR, "proxy.pid")
LOG_FILE = os.path.join(PROXY_DIR, "proxy.log")
SERVER_PY = os.path.join(PROXY_DIR, "server.py")
PORT = 8765
HOST = "127.0.0.1"
BASE_URL = f"http://{HOST}:{PORT}"

# ANSI Colors
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def is_running() -> bool:
    """Checks if the proxy server is responding on its port."""
    try:
        req = urllib.request.Request(f"{BASE_URL}/", headers={"User-Agent": "ZVault-CLI"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_pid() -> int | None:
    """Reads PID from pid file if valid and running."""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            # Check if process with this PID actually exists on Windows
            check = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"],
                capture_output=True, text=True
            )
            if str(pid) in check.stdout:
                return pid
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
            # Using cmd.exe 'start /min' to launch independent detached Windows process
            cmd = f'cmd.exe /c start "ZVault" /min "{python_exe}" "{SERVER_PY}"'
            subprocess.run(cmd, shell=True)
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

        # Wait up to 4 seconds for server to start
        started = False
        for _ in range(16):
            time.sleep(0.25)
            if is_running():
                started = True
                break

        if started:
            pid_label = f" (PID: {bg_pid})" if bg_pid else ""
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
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
            stopped = True
        except Exception:
            pass

    # If PID file was stale or missing, find process holding port 8765
    if not stopped or is_running():
        try:
            netstat = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            for line in netstat.stdout.splitlines():
                if f":{PORT}" in line and "LISTENING" in line:
                    parts = line.strip().split()
                    port_pid = parts[-1]
                    subprocess.run(["taskkill", "/F", "/PID", port_pid], capture_output=True)
                    stopped = True
        except Exception:
            pass

    # Wait for port to be released
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
            req = urllib.request.Request(f"{BASE_URL}/vault/status")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                print(f"  Total secrets in vault: {GREEN}{data.get('count', 0)}{RESET}")
                print(f"  Active .env files:")
                for ef in data.get("env_files", []):
                    print(f"    - {ef}")
        except Exception as e:
            print(f"  (Failed to query details: {e})")

        try:
            req = urllib.request.Request(f"{BASE_URL}/")
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

    # 1. Update config.json
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)

    env_list = config.setdefault("env_files", [])
    if abs_path not in env_list:
        env_list.append(abs_path)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

    # 2. If running, notify server dynamically
    if is_running():
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/vault/add-env",
                data=json.dumps({"path": abs_path}).encode("utf-8"),
                headers={"Content-Type": "application/json"}
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


def cmd_str(secret: str, label: str | None = None):
    """
    Adds a custom sensitive string to the vault with collision & duplicate handling.
    """
    if not secret:
        print(f"{RED}Error:{RESET} Secret string cannot be empty.")
        return

    # If server is running, use live API
    if is_running():
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/vault/add-secret",
                data=json.dumps({"secret": secret, "label": label or "STR"}).encode("utf-8"),
                headers={"Content-Type": "application/json"}
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

    # Fallback / offline mode: save to secrets.json
    secrets_path = os.path.join(PROXY_DIR, "secrets.json")
    stored = {}
    if os.path.exists(secrets_path):
        try:
            with open(secrets_path, "r", encoding="utf-8") as f:
                stored = json.load(f)
        except Exception:
            stored = {}

    # Check for exact duplicate secret
    existing_ph = None
    for ph, sec in stored.items():
        if sec == secret:
            existing_ph = ph
            break

    if existing_ph:
        print(f"{YELLOW}Secret already registered!{RESET} Reusing placeholder: {GREEN}{BOLD}{existing_ph}{RESET}")
        return

    # Generate unique placeholder with label and counter
    clean_label = (label or "STR").upper()
    next_idx = len(stored) + 1
    new_ph = f"__VAULT_{clean_label}_{next_idx:02d}__"
    stored[new_ph] = secret

    with open(secrets_path, "w", encoding="utf-8") as f:
        json.dump(stored, f, indent=2, ensure_ascii=False)

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
  zv str "<secret>" ["TAG"]  Add an ad-hoc secret string (with optional label)
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
            print(f"{RED}Usage:{RESET} zv str \"<secret>\" [\"<label>\"]")
            return
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
