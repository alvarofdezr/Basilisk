# 🐉 Basilisk EDR: Advanced Threat Defense Platform

<div align="center">

![Logo](https://img.shields.io/badge/Basilisk-EDR_v6.5-10b981?style=for-the-badge&logo=security&logoColor=white)

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-HTTPS%2F_TLS_1.2-lock?style=flat-square&color=critical)]()
[![Architecture](https://img.shields.io/badge/Architecture-Distributed_C2-blue?style=flat-square)](https://en.wikipedia.org/wiki/Command_and_control_(malware))
[![Status](https://img.shields.io/badge/Build-Stable_Enterprise-success?style=flat-square)]()

**Plataforma de Ciberseguridad Ofensiva/Defensiva. Combina monitorización forense en tiempo real, detección de malware basada en firmas (YARA) y análisis de comportamiento en memoria.**

[Reportar Bug](https://github.com/TU_USUARIO/basilisk/issues) · [Solicitar Feature](https://github.com/TU_USUARIO/basilisk/issues)

</div>

---

## 📋 Tabla de Contenidos
- [Resumen del Proyecto](#-resumen-del-proyecto)
- [Capacidades Defensivas](#-capacidades-defensivas)
- [Arquitectura (v6.5)](#-arquitectura-v67)
- [Instalación y Despliegue](#-instalación-y-despliegue)
- [Capturas de Pantalla](#-capturas-de-pantalla)
- [Roadmap](#-roadmap)

---

## ⚠️ Disclaimer

Uso Responsable: Basilisk es una herramienta de ingeniería de ciberseguridad defensiva. El autor no se hace responsable de daños causados por configuraciones erróneas, pérdida de datos o interrupciones de servicio derivadas de su uso. Úselo únicamente en entornos autorizados.

---

## 🔭 Resumen del Proyecto

**Basilisk EDR v6.5** (anteriormente *PySentinel*) es una solución completa de seguridad en el endpoint. A diferencia de un antivirus tradicional, Basilisk se centra en la **visibilidad total** y la **respuesta a incidentes**.

El sistema opera bajo una arquitectura **Cliente-Servidor (C2)** blindada con **HTTPS/TLS**, garantizando que las comunicaciones y comandos críticos no puedan ser interceptados. Incluye un motor de **Persistencia SQL** que asegura la integridad de los logs forenses ante reinicios o sabotajes.

---

## 🚀 Capacidades Defensivas

### 🧠 Detección Avanzada & Forense
* **Basilisk YARA Engine:** Motor de escaneo de malware basado en firmas. Detecta amenazas conocidas, webshells y patrones de ataque en memoria.
* **Memory Forensics:** Detección de técnicas de evasión como **Process Hollowing** y **Masquerading** (ej. un falso `svchost.exe` fuera de System32).
* **Process Hygiene:** Detección proactiva de **Bloatware y Telemetría** (Spyware comercial, Rastreadores de Microsoft, etc.).
* **FIM 3.0 (Blind Spot Fix):** Monitor de Integridad de Archivos capaz de detectar **Modificaciones**, **Creaciones** y **Eliminación de Evidencias** (borrado de logs).

### 🛡️ Hardening & Seguridad C2
* **Comunicaciones Cifradas:** Todo el tráfico viaja por el puerto **8443** bajo **TLS/SSL**.
* **Anti-DoS:** Throttling de heartbeats para evitar saturación del servidor.
* **Protección de Identidad:** Rate Limiting en login y gestión segura de sesiones con cookies cifradas.
* **SQL Persistence:** Cola de comandos y reportes persistentes en `c2_server.db`.

### ⚡ Respuesta Activa
* **USB Sentinel:** Detección instantánea de conexión/desconexión de dispositivos externos.
* **Network Defense:** Bloqueo interactivo de conexiones salientes sospechosas.
* **Kill Switch:** Terminación remota de procesos hostiles desde el Dashboard.

---

## 🏗️ Arquitectura (v6.5)

```plaintext
Basilisk/
├── agent/                      # CEREBRO DEL ENDPOINT
│   └── agent_core.py           # Orquestador de módulos y comunicación segura
├── server/                     # COMANDO Y CONTROL (C2)
│   ├── server.py               # API FastAPI + Gestión de WebSockets
│   ├── server_persistence.py   # Modelos ORM (SQLAlchemy)
│   ├── c2_server.db            # Base de Datos Forense
│   └── static/                 # Dashboard SOC (Cyberpunk UI)
├── basilisk/                   # LÓGICA DE NEGOCIO COMPARTIDA
│   ├── modules/                # Módulos de Defensa
│   │   ├── yara_scanner.py     # Motor YARA
│   │   ├── memory_scanner.py   # Forense de RAM
│   │   ├── fim.py              # Integridad de Archivos
│   │   └── ...
│   └── rules/                  # Firmas de detección (.yar)
├── config.yaml                 # Configuración Maestra
├── cert.pem & key.pem          # Certificados SSL (Generados localmente)
└── requirements.txt
```
---
## 📦 Instalación y Despliegue (Docker no actualizado!!!)
Prerrequisitos

- OS: Windows 10/11 (Agente), Linux/Windows (Servidor).

- Python: 3.10+.

- Privilegios: Administrador (Para acceso a memoria y terminación de procesos).

### 1. Clonar e Instalar Dependencias
```bash

git clone [https://github.com/alvarofdezr/basilisk.git](https://github.com/alvarofdezr/basilisk.git)
cd basilisk
pip install -r requirements.txt
```

### 2. Generar Certificados SSL (¡CRÍTICO!)

Basilisk v6.5 requiere HTTPS obligatorio. Genera tus certificados autofirmados:
```bash

# Opción con OpenSSL (Git Bash / Linux)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

# Opción Windows (Script Python incluido)
python generar_certs.py
```

### 3. Iniciar el Servidor C2 (Mando)

El servidor iniciará en modo seguro en el puerto 8443.
```bash

python server/server.py
# Salida esperada: 🐍 [SYSTEM] Basilisk C2 v6.5 Online (HTTPS/SQL)...
```

### 4. Desplegar el Agente (Endpoint)

En una nueva terminal (como Admin):
```bash

python agent/agent_core.py
# Salida esperada: 🛡️ Iniciando Basilisk Agent... [SUCCESS]
``` 

### 5. Acceso al SOC

Navega a: https://localhost:8443

- Usuario: admin

- Password: (Definido en config.yaml)


---

## 📸 Dashboard SOC

El nuevo panel de control v6.5 incluye visualización en tiempo real, modo oscuro profesional y clasificación de amenazas por iconos.

🗺️ Roadmap

    [x] v6.0: Arquitectura Distribuida C2.

    [x] v6.2: Persistencia SQL y Auth Unificada.

    [x] v6.4: Security Hardening (Rate Limit, Throttling, Sanitización),  Motor de Detección YARA

    [x] v6.5: Rebranding "Basilisk", Memory Forensics (Hollowing), Process Hygiene & Advanced FIM.

    [ ] v6.6 (Próximo): Network Isolation (Botón de Pánico / Firewall Kill Switch).

    [ ] v6.7: Live Shell Interactiva via WebSockets.

---

<div align="center">

Desarrollado por Alvaro Fernández Ramos Senior Cybersecurity Engineering Project

</div>