import time
import re
from .database import log_command

# Banner clasico de servidor Linux Ubuntu
UBUNTU_MOTD = (
    "\r\n"
    "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    " * Support:        https://ubuntu.com/advantage\r\n\r\n"
    "Last login: Tue Oct 20 08:14:22 2026 from 192.168.1.10\r\n"
)

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\r\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\r\n"
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\r\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\r\n"
    "alex:x:1000:1000:Alex:/home/alex:/bin/bash\r\n"
    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\r\n"
)

class FakeShell:
    """
    Emulador de terminal interactiva en memoria.
    REGLA DE ORO DE SEGURIDAD: Ningun comando se ejecuta en el sistema operativo real.
    Todo es respondido mediante respuestas sinteticas verosimiles.
    """
    def __init__(self, channel, session_id: str, ip: str, username: str):
        self.channel = channel
        self.session_id = session_id
        self.ip = ip
        self.username = username
        self.prompt = f"{username}@ubuntu-srv:~# "

    def send(self, text: str):
        """Envia texto formateado con retornos de carro para terminales SSH."""
        self.channel.send(text.encode("utf-8"))

    def run(self):
        """Bucle principal de la terminal interactiva."""
        self.send(UBUNTU_MOTD)
        self.send(self.prompt)

        cmd_buffer = []

        while True:
            try:
                char = self.channel.recv(1)
                if not char:
                    break

                # Manejo de Enter (\r o \n)
                if char in (b"\r", b"\n"):
                    self.send("\r\n")
                    raw_cmd = "".join(cmd_buffer).strip()
                    cmd_buffer = []

                    if raw_cmd:
                        # 1. Registrar en la base de datos para analisis forense
                        log_command(self.session_id, self.ip, self.username, raw_cmd)

                        # 2. Procesar el comando y enviar respuesta emulada
                        if not self.handle_command(raw_cmd):
                            break  # Comando exit o quit

                    self.send(self.prompt)

                # Manejo de Backspace / Borrado
                elif char in (b"\x7f", b"\x08"):
                    if cmd_buffer:
                        cmd_buffer.pop()
                        # Borrar visualmente en la terminal del atacante
                        self.send("\b \b")

                # Manejo de Ctrl+C
                elif char == b"\x03":
                    self.send("^C\r\n")
                    cmd_buffer = []
                    self.send(self.prompt)

                # Caracter regular tecleado
                else:
                    try:
                        decoded = char.decode("utf-8")
                        cmd_buffer.append(decoded)
                        self.send(decoded)  # Echo local
                    except UnicodeDecodeError:
                        pass

            except Exception:
                break

    def handle_command(self, cmd: str) -> bool:
        """
        Interpreta comandos comunes usados por atacantes y malware de botnets (como Mirai).
        Retorna False si el atacante quiere salir de la sesion.
        """
        lower = cmd.lower().strip()

        if lower in ("exit", "quit", "logout"):
            self.send("logout\r\nConnection to ubuntu-srv closed.\r\n")
            return False

        elif lower in ("whoami",):
            self.send(f"{self.username}\r\n")

        elif lower in ("id",):
            self.send("uid=0(root) gid=0(root) groups=0(root)\r\n")

        elif lower in ("uname -a", "uname -mrs", "uname"):
            self.send("Linux ubuntu-srv 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 GNU/Linux\r\n")

        elif lower in ("pwd",):
            self.send("/root\r\n")

        elif lower.startswith("ls") or lower in ("dir",):
            self.send("Desktop  Documents  Downloads  backup.tar.gz  config.json\r\n")

        elif "cat /etc/passwd" in lower:
            self.send(FAKE_PASSWD)

        elif "cat /etc/shadow" in lower:
            self.send("root:$6$salt123$qO4ZtPz34qL5XyZ5k7a0w.hash:19280:0:99999:7:::\r\n")

        elif lower.startswith("wget ") or lower.startswith("curl "):
            # Atacante intentando descargar un payload o dropper de malware
            url_match = re.search(r'https?://[^\s]+', cmd)
            target_url = url_match.group(0) if url_match else "remote_file"
            
            self.send(f"--2026-10-20 09:15:00--  {target_url}\r\n")
            self.send("Resolving host... connected.\r\n")
            self.send("HTTP request sent, awaiting response... 200 OK\r\n")
            self.send("Length: 42080 (41K) [application/x-sh]\r\n")
            self.send("Saving to: 'script.sh'\r\n\r\n")
            self.send("script.sh           100%[===================>]  41.09K  --.-KB/s    in 0.04s\r\n\r\n")
            self.send("2026-10-20 09:15:01 (1.02 MB/s) - 'script.sh' saved [42080/42080]\r\n")

        elif lower.startswith("chmod ") or lower.startswith("rm "):
            # Comandos de preparacion de malware, retornar exito silencioso
            pass

        elif lower.startswith("cat "):
            self.send("File not found or permission denied.\r\n")

        elif lower in ("clear",):
            self.send("\033[H\033[J")

        elif lower in ("help", "man"):
            self.send("GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\r\n")

        else:
            first_word = cmd.split()[0]
            self.send(f"bash: {first_word}: command not found\r\n")

        return True
