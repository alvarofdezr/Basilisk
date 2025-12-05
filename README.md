# 🐉 Basilisk EDR: Advanced Threat Defense Platform

<div align="center">

![Logo](https://img.shields.io/badge/Basilisk-EDR_v6.7.0-10b981?style=for-the-badge&logo=security&logoColor=white)

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-HTTPS%2F_TLS_1.3-lock?style=flat-square&color=critical)]()
[![Architecture](https://img.shields.io/badge/Architecture-Distributed_C2-blue?style=flat-square)](https://en.wikipedia.org/wiki/Command_and_control_(malware))
[![Status](https://img.shields.io/badge/Build-Stable_Enterprise-success?style=flat-square)]()

**Plataforma de Ciberseguridad Ofensiva/Defensiva. Combina monitorización forense en tiempo real, detección de malware basada en firmas (YARA) y análisis de comportamiento en memoria.**

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

**Basilisk EDR v6.6.0** es una solución completa de seguridad en el endpoint centrada en la **visibilidad total** y la **respuesta a incidentes**.

El sistema opera bajo una arquitectura **Cliente-Servidor (C2)** blindada con **HTTPS/TLS**, garantizando que las comunicaciones y comandos críticos no puedan ser interceptados. Incluye un motor de **Persistencia SQL** thread-safe que asegura la integridad de los logs forenses.

---

## 🚀 Capacidades Defensivas (v6.7 Update)

### 🧠 Detección & Visibilidad
* **Global Threat Map:** Visualización interactiva de conexiones en tiempo real con Geolocalización de amenazas (GeoIP).
* **Smart Process Monitor:** Escaneo diferencial (Delta Scanning) con detección de **Process Hollowing** y telemetría oculta.
* **Intelligent Port Audit:** Clasificación de riesgo por colores y detección de exposición a Internet.
* **Compliance Scanner:** Auditoría automática de hardening (Firewall, UAC, Windows Defender, Parches).

### ⚡ Rendimiento & Arquitectura
* **Non-Blocking Core:** Arquitectura asíncrona basada en hilos (`ThreadPoolExecutor`) para operaciones pesadas (YARA/FIM) sin congelar el agente.
* **Smart FIM:** Hashing inteligente con caché de metadatos para reducir el I/O de disco en un 99%.

### 🛡️ Seguridad & Infraestructura
* **Zero-Config PKI:** Generación automática de certificados SSL/TLS (X.509) al arranque.
* **Enterprise Auth:** Hashing de contraseñas con **Argon2id** (resistente a ataques GPU).
* **Network Isolation:** Capacidad de aislar (y restaurar) hosts comprometidos de la red.

---
## 🏗️ Arquitectura (v6.5)

```plaintext
Basilisk/
├── certs/                      # ALMACEN DE CERTIFICADOS
│   └── cert.pem                # Certificado
│   └── key.pem                 # Clave
├── agent/                      # CEREBRO DEL ENDPOINT
│   └── agent_core.py           # Orquestador de módulos y comunicación segura
├── server/                     # COMANDO Y CONTROL (C2)
│   ├── server.py               # API FastAPI + Gestión de WebSockets
│   ├── server_persistence.py   # Modelos ORM (SQLAlchemy)
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
## 📦 Instalación y Despliegue

### Prerrequisitos

- Python: 3.10+.

- Privilegios: Administrador (Para acceso a memoria y terminación de procesos).

### 1. Clonar e Instalar Dependencias
```bash

git clone [https://github.com/alvarofdezr/basilisk.git](https://github.com/alvarofdezr/basilisk.git)
cd basilisk
pip install -r requirements.txt
```

### 2. Iniciar el Servidor C2 (Mando)

El servidor iniciará en modo seguro en el puerto 8443.
```bash

python server/server.py
# Salida esperada: 🐍 [SYSTEM] Basilisk C2 v6.6 Online (HTTPS/SQL)...
```

### 3. Desplegar el Agente (Endpoint)

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

## 🛠️ Tech Stack
* **Core:** Python 3.10+, FastAPI (Async), SQLAlchemy.
* **Security:** Argon2-cffi, Cryptography (X.509), YARA-Python.
* **Frontend:** Bootstrap 5, Vis.js (Network Graph), Chart.js.
* **System:** Psutil, Ctypes (WinAPI), WinReg.

---

<div align="center">

Desarrollado por Alvaro Fernández Ramos Senior Cybersecurity Engineering Project

</div>