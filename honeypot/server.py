import os
import socket
import threading
import uuid
import logging
import paramiko

from .database import init_db, log_auth_attempt
from .threat_intel import get_ip_intel
from .fake_shell import FakeShell

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

HOST_KEY_FILE = os.environ.get("HOST_KEY_FILE", "server.key")
LISTEN_PORT = int(os.environ.get("HONEYPOT_PORT", 2222))
LISTEN_IP = os.environ.get("HONEYPOT_HOST", "0.0.0.0")

# Credenciales trampa que permiten acceso a la shell simulada
TRAP_CREDENTIALS = {
    ("root", "root"),
    ("root", "123456"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("ubuntu", "ubuntu"),
    ("user", "user"),
    ("test", "test")
}

def get_or_create_host_key():
    """Genera o carga la clave privada RSA del servidor SSH."""
    if not os.path.exists(HOST_KEY_FILE):
        logging.info(f"Generando nueva clave RSA de host en {HOST_KEY_FILE}...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_FILE)
    return paramiko.RSAKey(filename=HOST_KEY_FILE)

class HoneypotSSHServer(paramiko.ServerInterface):
    """Implementacion de la interfaz del servidor SSH con Paramiko."""

    def __init__(self, client_ip: str, client_port: int):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()
        self.authenticated_user = None
        self.session_id = str(uuid.uuid4())[:8]

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """Audita el intento de login y decide si dejarlo pasar a la trampa."""
        geo_info = get_ip_intel(self.client_ip)
        
        # Permitir login si coincide con las credenciales trampa para capturar comandos
        is_success = (username, password) in TRAP_CREDENTIALS
        status = "SUCCESS" if is_success else "FAILED"

        logging.warning(
            f"[AUTH] IP={self.client_ip} ({geo_info.get('country')}) | User='{username}' Pass='{password}' -> {status}"
        )
        
        # Guardar en SQLite
        log_auth_attempt(
            ip=self.client_ip,
            port=self.client_port,
            username=username,
            password=password,
            status=status,
            geo_info=geo_info
        )

        if is_success:
            self.authenticated_user = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def handle_client(client_socket, client_addr, host_key):
    """Maneja la conexion de un atacante en un hilo independiente."""
    client_ip, client_port = client_addr
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        
        server = HoneypotSSHServer(client_ip, client_port)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        channel = transport.accept(20)
        if channel is None:
            return

        server.event.wait(10)
        if not server.event.is_set():
            channel.close()
            return

        logging.info(f"[SESSION START] Atacante {client_ip} ingreso como '{server.authenticated_user}' (Session: {server.session_id})")

        # Iniciar la terminal simulada segura
        shell = FakeShell(channel, server.session_id, client_ip, server.authenticated_user or "root")
        shell.run()

        logging.info(f"[SESSION END] Sesion terminada para {client_ip} (Session: {server.session_id})")
        channel.close()

    except Exception as e:
        logging.debug(f"Excepcion en conexion de {client_ip}: {e}")
    finally:
        client_socket.close()

def start_server():
    """Punto de entrada principal del servidor honeypot."""
    init_db()
    host_key = get_or_create_host_key()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_IP, LISTEN_PORT))
    server_sock.listen(100)

    logging.info(f"🛡️ ShadowSSH Honeypot escuchando en {LISTEN_IP}:{LISTEN_PORT}...")

    while True:
        try:
            client_socket, client_addr = server_sock.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_socket, client_addr, host_key),
                daemon=True
            )
            t.start()
        except KeyboardInterrupt:
            logging.info("Deteniendo Honeypot...")
            break
        except Exception as e:
            logging.error(f"Error en bucle de recepcion: {e}")

if __name__ == "__main__":
    start_server()
