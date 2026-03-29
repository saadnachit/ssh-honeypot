#!/usr/bin/env python3
import socket
import threading
import json
import os
import datetime
import traceback
import shlex

import paramiko

# Seccomp (si dispo)
try:
    import pyseccomp as seccomp
except Exception:
    seccomp = None

LOG_PATH = "/var/log/honeypot/ssh.jsonl"
HOST = "0.0.0.0"
PORT = 2222
HOST_KEY_PATH = "/opt/ssh_honeypot/keys/host_rsa"


def now_iso():
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def log_event(event: dict):
    event.setdefault("timestamp", now_iso())
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[LOG ERROR] {e}")


def simulate_command(cmd: str, username: str | None) -> str | None:
    """
    Simule quelques commandes de base pour donner l'illusion d'un vrai shell.
    """
    username = username or "user"

    try:
        tokens = shlex.split(cmd)
    except Exception:
        tokens = cmd.strip().split()

    if not tokens:
        return ""

    c = tokens[0]
    args = tokens[1:]

    # Aide
    if c in ("help", "?"):
        return (
            "Available commands (simulated):\n"
            "  whoami, pwd, uname [-a], ls [-la] [path], id\n"
            "  cat /etc/passwd\n"
        )

    # whoami
    if c == "whoami":
        return f"{username}\n"

    # id
    if c == "id":
        return (
            f"uid=1000({username}) gid=1000({username}) "
            f"groups=1000({username}),27(sudo)\n"
        )

    # pwd
    if c == "pwd":
        return f"/home/{username}\n"

    # uname
    if c == "uname":
        if "-a" in args:
            return (
                "Linux host 5.15.0-86-generic #96-Ubuntu SMP x86_64 GNU/Linux\n"
            )
        return "Linux\n"

    # ls
    if c == "ls":
        show_all = any(a.startswith("-") and "a" in a for a in args)
        target = None
        for a in args:
            if not a.startswith("-"):
                target = a
                break

        def home_entries():
            base = ["Documents", "Downloads", "script.sh"]
            if show_all:
                return [".bashrc", ".profile"] + base
            return base

        if target in (None, ".", "~"):
            return "  ".join(home_entries()) + "\n"

        if target == "/":
            return (
                "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  "
                "root  run  sbin  srv  sys  tmp  usr  var\n"
            )

        if target in ("/etc", "etc"):
            return "passwd  shadow  hosts  hostname  resolv.conf\n"

        if target in (f"/home/{username}", "home", "~/", f"/home/{username}/"):
            return "  ".join(home_entries()) + "\n"

        return f"ls: cannot access '{target}': No such file or directory\n"

    # cat
    if c == "cat":
        if args and args[0] in ("/etc/passwd", "etc/passwd"):
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                f"{username}:x:1000:1000:{username}:/home/{username}:/bin/bash\n"
            )
        target = args[0] if args else ""
        return f"cat: {target}: No such file or directory\n"

    # Commande inconnue
    return None


class SSHHoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_addr):
        super().__init__()
        self.client_addr = client_addr
        self.event = threading.Event()
        self.exec_command = None
        self.username = None

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        """
        Accepte toujours l'authentification, enregistre le couple user/pass.
        """
        self.username = username
        log_event({
            "event": "auth_attempt",
            "src_ip": self.client_addr[0],
            "src_port": self.client_addr[1],
            "username": username,
            "password": password,
            "success": True
        })
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        # On accepte un PTY pour l'illusion, même si on ne gère pas tout
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_exec_request(self, channel, command):
        try:
            cmd = (
                command.decode("utf-8", errors="replace")
                if isinstance(command, (bytes, bytearray))
                else str(command)
            )
        except Exception:
            cmd = str(command)
        self.exec_command = cmd
        return True


def apply_seccomp():
    """
    Applique une politique Seccomp simple si pyseccomp est disponible.
    """
    if not seccomp:
        log_event({"event": "seccomp", "status": "not_available"})
        return False
    try:
        # Politique par défaut : tout autoriser
        f = seccomp.SyscallFilter(seccomp.SCMP_ACT_ALLOW)
        # Action de blocage : renvoyer EPERM (errno 13)
        deny = seccomp.SCMP_ACT_ERRNO(13)
        # Liste noire de syscalls interdits
        blacklist = [
            "execve", "execveat",
            "fork", "vfork",
            "ptrace",
            "kexec_load", "kexec_file_load",
            "init_module", "finit_module", "delete_module",
            "mount", "umount2", "pivot_root",
            "reboot",
        ]
        for name in blacklist:
            try:
                f.add_rule(deny, name)
            except Exception:
                # Certains syscalls peuvent ne pas exister selon le noyau
                pass
        f.load()
        log_event({
            "event": "seccomp",
            "status": "enabled",
            "policy": "default-allow + deny critical exec/sysadmin"
        })
        return True
    except Exception as e:
        log_event({
            "event": "seccomp",
            "status": "enable_failed",
            "error": str(e)
        })
        return False


def get_or_create_host_key() -> paramiko.RSAKey:
    """
    Charge la clé hôte RSA si elle existe, sinon en génère une nouvelle.
    """
    try:
        if os.path.exists(HOST_KEY_PATH):
            return paramiko.RSAKey.from_private_key_file(HOST_KEY_PATH)

        os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
        os.chmod(HOST_KEY_PATH, 0o600)
        log_event({
            "event": "hostkey",
            "status": "created",
            "path": HOST_KEY_PATH
        })
        return key
    except Exception as e:
        log_event({
            "event": "hostkey",
            "status": "error",
            "error": str(e)
        })
        # Fallback : clé éphémère en mémoire
        return paramiko.RSAKey.generate(2048)


def send_prompt(chan: paramiko.Channel, username: str | None):
    """
    Affiche un prompt proprement en effaçant la ligne courante.
    Permet de limiter les problèmes d'affichage décalé.
    """
    prompt_user = username or "user"
    prompt = f"{prompt_user}@host:~$ "
    # Retour au début de la ligne + effacement de la ligne (ANSI \x1b[2K)
    chan.send(b"\r\x1b[2K")
    chan.send(prompt.encode("utf-8"))


def handle_client(client_sock, client_addr, host_key):
    transport = None
    chan = None
    server = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(host_key)
        server = SSHHoneypotServer(client_addr)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            return

        log_event({
            "event": "session_start",
            "src_ip": client_addr[0],
            "src_port": client_addr[1],
            "username": getattr(server, "username", None)
        })

        # Cas "ssh host 'commande'"
        if server.exec_command:
            log_event({
                "event": "exec_command",
                "src_ip": client_addr[0],
                "src_port": client_addr[1],
                "username": getattr(server, "username", None),
                "command": server.exec_command
            })
            out = simulate_command(server.exec_command, getattr(server, "username", None))
            if out is not None:
                chan.send(out.encode("utf-8"))
                chan.send_exit_status(0)
            else:
                msg = f"{server.exec_command}: command not found\r\n"
                chan.send(msg.encode("utf-8"))
                chan.send_exit_status(127)
            chan.close()
            return

        # Bannière "Linux"
        # Bannière "Linux"
        banner = (
            "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15 x86_64)\r\n"
            "Type 'help' for help.\r\n"
        )
        chan.send(banner.encode("utf-8"))

        prompt_user = getattr(server, "username", "user")
        send_prompt(chan, prompt_user)

        current_line = ""

        while True:
            data = chan.recv(1024)
            if not data:
                break

            for ch in data:
                c = chr(ch)

                # Retour chariot ou nouvelle ligne => exécuter la commande
                if c in ("\r", "\n"):
                    # Aller à la ligne
                    chan.send(b"\r\n")

                    cmd = current_line.strip()
                    # Ligne vide : juste prompt
                    if not cmd:
                        current_line = ""
                        send_prompt(chan, prompt_user)
                        continue

                    # Log de la commande
                    log_event({
                        "event": "shell_command",
                        "src_ip": client_addr[0],
                        "src_port": client_addr[1],
                        "username": getattr(server, "username", None),
                        "command": cmd
                    })

                    # Sortie du shell
                    if cmd in ("exit", "logout", "quit"):
                        chan.send(b"logout\r\n")
                        chan.send_exit_status(0)
                        chan.close()
                        return

                    # Exécution simulée
                    out = simulate_command(
                        cmd,
                        getattr(server, "username", None)
                    )
                    if out is not None:
                        chan.send(out.encode("utf-8"))
                    else:
                        chan.send(
                            f"bash: {cmd}: command not found\r\n".encode("utf-8")
                        )

                    # Réinitialiser la ligne et réafficher le prompt
                    current_line = ""
                    send_prompt(chan, prompt_user)
                    continue

                # Gestion du backspace
                if ch in (8, 127):  # Backspace ou DEL
                    if current_line:
                        current_line = current_line[:-1]
                        # Effacer le dernier caractère à l'écran
                        chan.send(b"\b \b")
                    continue

                # Caractère imprimable classique
                if 32 <= ch <= 126:  # caractères ASCII visibles
                    current_line += c
                    chan.send(bytes([ch]))  # écho immédiat
                    continue

                # On ignore les autres caractères de contrôle
                continue
    except Exception as e:
        log_event({
            "event": "server_error",
            "error": str(e),
            "trace": traceback.format_exc()
        })
    finally:
        try:
            if chan is not None and not chan.closed:
                chan.close()
        except Exception:
            pass
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass
        if server is not None:
            log_event({
                "event": "session_close",
                "src_ip": client_addr[0],
                "src_port": client_addr[1],
                "username": getattr(server, "username", None)
            })

def run_server(host=HOST, port=PORT):
    # Clé hôte persistante
    host_key = get_or_create_host_key()

    # Active Seccomp (si dispo)
    apply_seccomp()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    print(f"[+] SSH honeypot listening on {host}:{port}")

    try:
        while True:
            client, addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client, addr, host_key),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[!] Stopping honeypot...")
    finally:
        srv.close()


if __name__ == "__main__":
    run_server()
