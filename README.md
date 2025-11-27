# PySentinel EDR: Enterprise Security Suite 🛡️

<div align="center">

![Logo](https://img.shields.io/badge/PySentinel-EDR_v6.2-0052cc?style=for-the-badge&logo=security&logoColor=white)

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Client%2FServer_C2-blue?style=flat-square)](https://en.wikipedia.org/wiki/Command_and_control_(malware))
[![Status](https://img.shields.io/badge/Status-Stable_Persistence-success?style=flat-square)]()
[![Database](https://img.shields.io/badge/Database-SQLite_Persistent-0073AA?style=flat-square&logo=sqlite&logoColor=white)]()

**Sistema de Detección y Respuesta en el Endpoint (EDR) distribuido. Combina la monitorización forense en el Agente con un Servidor C2 persistente y un Dashboard SOC moderno.**

[Reportar Bug](https://github.com/tu_usuario/PySentinel/issues) · [Solicitar Feature](https://github.com/tu_usuario/PySentinel/issues)

</div>

---

## 📋 Tabla de Contenidos
- [Resumen del Proyecto](#-resumen-del-proyecto)
- [Características Principales](#-características-principales)
- [Arquitectura del Sistema (v6.2)](#-arquitectura-del-sistema-v62)
- [Instalación y Despliegue](#-instalación-y-despliegue)
- [Configuración](#-configuración)
- [Próximos Pasos (Roadmap)](#-próximos-pasos-roadmap)

---

## 🔭 Resumen del Proyecto

**PySentinel v6.2** marca la transición a una arquitectura de **Servidor de Mando y Control (C2)** persistente. El sistema ha evolucionado de una herramienta local a una solución distribuida capaz de gestionar múltiples endpoints (Agentes) desde una interfaz web centralizada.

El **Servidor C2** utiliza una base de datos **SQLite persistente (SQLAlchemy)** para garantizar que **ningún log de incidente ni estado de agente se pierda** tras un reinicio. La autenticación es unificada (**SHA-512**) para proteger tanto el acceso al Dashboard como los comandos críticos.

---

## 🚀 Características Principales

### 🛡️ Mando y Control (C2) & Persistencia
* **Arquitectura Distribuida:** Servidor C2 (FastAPI) y Agente EDR (Python 3.10+).
* **Persistencia de Datos:** Logs e historial de Agentes se almacenan en `c2_server.db` (SQLite/SQLAlchemy).
* **Seguridad Unificada:** Autenticación de acceso web y comandos críticos protegida por **SHA-512** centralizado en `config.yaml`.
* **Respuesta Remota:** Capacidad de enviar órdenes `KILL:PID` desde el Dashboard.

### 🔍 Detección Forense Avanzada
* **Canary Sentry:** Detección de modificación/cifrado en tiempo real (anti-ransomware).
* **Auditoría de Procesos:** Detección de *Masquerading* y ejecución desde `%TEMP%`.
* **Port/Net Monitor:** Vigilancia de conexiones salientes y puertos *Listening*.
* **FIM 2.0:** Algoritmo de Hashing inteligente (Cabecera/Pie) para escaneos rápidos.

### 🖥️ SOC Dashboard (v6.1.1)
* **Diseño SOC:** Interfaz modernizada con vista de Agentes tipo Heatmap.
* **Métricas en Vivo:** Visualización de **CPU y RAM** en tiempo real en las tarjetas de Agente.
* **Inspección Tabular:** Navegación por pestañas **(Procesos / Puertos)** dentro del modal de inspección del agente.

---

## 🏗️ Arquitectura del Sistema (v6.2)

El proyecto está separado en dos aplicaciones distintas que consumen un paquete de lógica compartida (`pysentinel`):

```plaintext
PySentinel/
├── agent/                      # Cliente EDR: Colecta datos, obedece comandos.
│   └── agent_core.py           
├── server/                     # Servidor C2: App FastAPI, gestión de logs y BBDD.
│   ├── server.py               
│   ├── server_persistence.py   # Modelos ORM (SQLAlchemy)
│   ├── c2_server.db            # Base de Datos Persistente
│   └── static/                 # Dashboard Web (index.html, login.html)
├── pysentinel/                 # PAQUETE DE LÓGICA COMPARTIDA
│   ├── core/                   # (Config, DB Manager local)
│   └── modules/                # (FIM, Anti-Ransomware, Threat Intel)
├── config.yaml                 # Configuración Maestra Única
└── requirements.txt
```
## 📦 Instalación y Despliegue
Prerrequisitos

- Sistema Operativo: Windows 10/11 (Requiere acceso a Win32 API).

- Python: 3.10 o superior.

- Privilegios: Ejecución como Administrador obligatoria.

1. Clonar el repositorio:
```Bash
git clone [https://github.com/TU_USUARIO/PySentinel.git](https://github.com/TU_USUARIO/PySentinel.git)
cd PySentinel
```

2. Configuración de Seguridad
- Abre config.yaml
- Genera el hash SHA-512 de tu contraseña maestra:
```Bash
import hashlib
print(hashlib.sha512("tu_password".encode()).hexdigest())
```

3. Iniciar el Servidor C2
- Ejecuta Uvicorn desde la raíz del proyecto para resolver correctamente las rutas de importación:
```bash
uvicorn server.server:app --reload --host 0.0.0.0 --port 8000
```
4. Desplegar y Conectar el Agente
- Abre una segunda terminal (como administrador).
- Ejecuta el Agente (el Heartbeat se conectará automáticamente):
```Bash
python agent/agent_core.py
```
- Accede al Dashboard: http://127.0.0.1:8000

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

[x] v5.0: EDR Local y Gráficos SOC.

[x] v6.0: Arquitectura C2 Distribuida.

[x] v6.2: Persistencia SQL y Auth Unificada (Estado Actual).

[ ] v6.3: Live Shell Interactiva: Implementar comandos bidireccionales de baja latencia (ej. whoami, netstat) en el modal de inspección.

[ ] v6.4: Empaquetado del Agente a .exe (PyInstaller) para despliegue sin dependencias.

[ ] v7.0: Detección de Amenazas basada en Reglas YARA.

## ⚠️ Disclaimer

Uso Responsable: PySentinel es una herramienta de seguridad defensiva. Incluye capacidades de terminación de procesos ("Kill Switch"). El autor no se hace responsable de daños causados por configuraciones erróneas, pérdida de datos o interrupciones de servicio derivadas de su uso. Úselo bajo su propia responsabilidad y preferiblemente en entornos controlados.

<div align="center">

Desarrollado por Álvaro Fernández Ramos

Senior Cybersecurity Engineering Project

</div>