# PySentinel - Security & Health Dashboard 🛡️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Status](https://img.shields.io/badge/Status-Active-success)
![Security](https://img.shields.io/badge/Focus-Blue%20Team-red)

**PySentinel** es una solución integral de monitorización de host (HIDS) diseñada para Ingeniería de Sistemas y Ciberseguridad. Combina la detección de intrusiones en tiempo real con la monitorización de la salud del sistema (CPU/RAM) en un Dashboard moderno.

El objetivo del proyecto es demostrar una arquitectura de software robusta, modular y persistente, capaz de operar como herramienta de defensa activa.

## 🚀 Características Principales

### 🛡️ Ciberseguridad (Blue Team)
* **FIM (File Integrity Monitor):** Detección en tiempo real de creación, modificación y eliminación de archivos críticos usando SHA-256.
* **Intrusion Detection (Log Watcher):** Análisis continuo de logs mediante Regex para detectar ataques de fuerza bruta y patrones anómalos.
* **Alertas Remotas:** Integración con la **API de Telegram** para recibir notificaciones de seguridad directamente en el móvil.

### 🖥️ Ingeniería y Salud del Sistema
* **Monitor de Recursos:** Visualización en tiempo real del uso de **CPU, RAM y Disco** mediante integración con el Kernel (`psutil`).
* **Persistencia de Datos:** Base de datos SQLite integrada para almacenar un historial forense de eventos.
* **Reporting:** Capacidad de exportar incidentes a **CSV** para auditorías externas.

### ⚙️ Arquitectura Técnica
* **Frontend:** Interfaz moderna (Dark Mode) construida con `customtkinter`, implementando hilos (threading) para evitar bloqueos de UI.
* **Backend:** Lógica desacoplada del frontend. Uso de patrones de diseño para la gestión de base de datos.
* **Configuración:** Sistema agnóstico mediante `config.yaml`, separando código de datos sensibles.

## 📦 Instalación y Uso

1.  **Clonar el repositorio:**
    ```bash
    git clone [https://github.com/alvarofdezr/PySentinel.git](https://github.com/alvarofdezr/PySentinel.git)
    cd PySentinel
    ```

2.  **Instalar dependencias:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configuración:**
    El sistema requiere un archivo `config.yaml`. Usa la plantilla proporcionada:
    ```bash
    # Copia la plantilla para crear tu configuración local
    cp config.example.yaml config.yaml
    ```
    *Edita `config.yaml` para añadir tu Token de Telegram y las carpetas a vigilar.*

4.  **Ejecutar:**
    ```bash
    python gui.py
    ```

## 🛠️ Estructura del Proyecto

```text
PySentinel/
├── gui.py                 # Controlador principal y GUI (Dashboard)
├── config.yaml            # (Ignorado por Git) Configuración local
├── pysentinel/
│   ├── core/
│   │   ├── database.py    # Gestión de SQLite y Exportación CSV
│   │   └── config.py      # Loader de configuración YAML
│   ├── modules/
│   │   ├── fim.py         # Motor de integridad de archivos
│   │   └── log_watcher.py # Motor de análisis de logs
│   └── utils/
│       ├── notifier.py    # Cliente API de Telegram
│       ├── system_monitor.py # Sensor de CPU/RAM (psutil)
│       └── logger.py      # Logging rotativo
└── ...