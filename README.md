# PySentinel EDR: Enterprise Security Suite 🛡️

<div align="center">

![Logo](https://img.shields.io/badge/PySentinel-EDR_v5.0-0052cc?style=for-the-badge&logo=security&logoColor=white)

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production_Ready-success?style=flat-square)]()
[![Security](https://img.shields.io/badge/Threat_Intel-VirusTotal-blueviolet?style=flat-square&logo=virustotal&logoColor=white)](https://www.virustotal.com/)

**Un sistema de Detección y Respuesta en el Endpoint (EDR) de próxima generación, diseñado para la monitorización forense, defensa activa y análisis de amenazas en tiempo real.**

[Reportar Bug](https://github.com/tu_usuario/PySentinel/issues) · [Solicitar Feature](https://github.com/tu_usuario/PySentinel/issues)

</div>

---

## 📋 Tabla de Contenidos
- [Resumen del Proyecto](#-resumen-del-proyecto)
- [Características Principales](#-características-principales)
- [Arquitectura del Sistema](#-arquitectura-del-sistema)
- [Instalación y Despliegue](#-instalación-y-despliegue)
- [Configuración](#-configuración)
- [Compilación (Binario)](#-compilación-binario)
- [Roadmap](#-roadmap)
- [Disclaimer](#-disclaimer)

---

## 🔭 Resumen del Proyecto

**PySentinel v5.0** no es un simple antivirus. Es una suite de ciberseguridad modular que implementa principios de **Zero Trust** y **Defensa en Profundidad**. 

Utilizando heurística avanzada, trampas tipo "Canary" y análisis de inteligencia de amenazas en la nube, PySentinel protege estaciones de trabajo críticas contra Ransomware, persistencia en el registro y exfiltración de datos, ofreciendo un **SOC Dashboard** visual para la toma de decisiones inmediata.

---

## 🚀 Características Principales

### 🛡️ Defensa Activa & Anti-Ransomware
* **Canary Sentry:** Despliegue de señuelos criptográficos ocultos. Detección de modificación/cifrado en <5ms.
* **Kill Switch Automatizado:** Terminación forzosa de procesos (`SIGKILL`) que violan políticas de red o integridad.
* **Registry Monitor:** Vigilancia de claves de persistencia (`Run`, `RunOnce`) para detectar Backdoors y RATs.

### 🔍 Análisis Forense & Threat Intel
* **Integración VirusTotal:** Consulta de hashes en tiempo real contra +70 motores antivirus (API v3).
* **Auditoría de Procesos:** Detección de *Masquerading* (falsos procesos de sistema) y ejecución desde directorios temporales (`%TEMP%`).
* **Port Scanner:** Monitorización en tiempo real de puertos *Listening* (TCP/UDP) y asociación de PID/Servicio.

### 📊 FIM 2.0 (File Integrity Monitor)
* **Smart Hashing Algorithm:** Hashing híbrido (Cabecera/Pie) para archivos >50MB, permitiendo escaneos de Terabytes sin latencia.
* **Baseline Snapshots:** Creación de líneas base de integridad protegidas criptográficamente (SHA-512).

### 🖥️ SOC Dashboard
* **Métricas en Vivo:** Gráficos de anillos y barras (`matplotlib`) para visualización de incidentes.
* **Health Score:** Algoritmo de puntuación de salud del sistema (0-100%) dinámico.
* **Dark Mode UI:** Interfaz optimizada para entornos de baja luminosidad (SOCs).

---

## 🏗️ Estructura de Ficheros
```text
PySentinel/
├── gui.py                  # Frontend (CustomTkinter + Matplotlib)
├── config.yaml             # Configuración Maestra
├── pysentinel/
│   ├── core/               # DB Manager & Config Loader (Typed)
│   ├── modules/            # Motores de Detección Independientes
│   │   ├── anti_ransomware.py
│   │   ├── process_monitor.py
│   │   ├── registry_monitor.py
│   │   ├── threat_intel.py
│   │   └── ...
│   └── utils/              # Generador PDF, Logger, Crypto
└── requirements.txt        # Dependencias
```
## 📦 Instalación y Despliegue
Prerrequisitos

- Sistema Operativo: Windows 10/11 (Requiere acceso a Win32 API).

- Python: 3.10 o superior.

- Privilegios: Ejecución como Administrador obligatoria.

Instalación Rápida (Dev)

1. Clonar el repositorio:
```Bash
git clone [https://github.com/TU_USUARIO/PySentinel.git](https://github.com/TU_USUARIO/PySentinel.git)
cd PySentinel
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```
3. Ejecutar:
```Bash
python gui.py
```

## ⚙️ Configuración

El sistema se gobierna mediante config.yaml. Es crucial configurar el hash de administrador y la API Key para funcionalidad completa.
YAML
```yaml
# config.yaml

monitoring:
  directories:
    - "C:/Users/Admin/Documents/Confidencial"
    - "C:/Proyectos"

network:
  whitelist:
    - "chrome.exe"
    - "python.exe"
    - "code.exe"

security:
  active_response: true                 # true = El EDR matará procesos hostiles
  admin_password_hash: "TU_HASH_SHA512" # Generar con hashlib.sha512('pass').hexdigest()
  virustotal_api_key: "TU_API_KEY_AQUI" # Opcional: Para análisis en la nube

notifications:
  telegram_token: ""
  telegram_chat_id: ""
```

## 🔨 Compilación (Binario)

Para distribuir PySentinel como una herramienta portable (.exe) sin dependencias externas:
```powerShell

pyinstaller --noconsole --onefile --name="PySentinel_EDR_v5.0_Enterprise" \
    --hidden-import=PIL \
    --hidden-import=matplotlib \
    --collect-all=customtkinter \
    --collect-all=matplotlib \
    --add-data "config.example.yaml;." \
    --icon=app_icon.ico \
    gui.py
```
  - Nota: El ejecutable resultante en /dist debe ir siempre acompañado del archivo config.yaml para funcionar.

## 🗺️ Roadmap

[x] v3.0: Dashboard GUI y Monitorización Básica.

[x] v4.0: FIM con Snapshots y Anti-Ransomware.

[x] v4.3: Auditoría de Puertos y Procesos (Forensic).

[x] v5.0: Threat Intel (VirusTotal), Persistencia Registro y Gráficos SOC.

[ ] v6.0: Detección basada en reglas YARA (.yar).

[ ] v6.5: Agente C2 remoto vía Telegram Bot bidireccional.

## ⚠️ Disclaimer

Uso Responsable: PySentinel es una herramienta de seguridad defensiva. Incluye capacidades de terminación de procesos ("Kill Switch"). El autor no se hace responsable de daños causados por configuraciones erróneas, pérdida de datos o interrupciones de servicio derivadas de su uso. Úselo bajo su propia responsabilidad y preferiblemente en entornos controlados.

<div align="center">

Desarrollado por Álvaro Fernández Ramos

Senior Cybersecurity Engineering Project

</div>