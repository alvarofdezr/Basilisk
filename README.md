# PySentinel - Advanced EDR & Security Hub 🛡️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-v2.0%20(Stable)-success)

**PySentinel** es una herramienta de defensa activa (EDR - Endpoint Detection and Response) desarrollada en Python. A diferencia de los antivirus tradicionales, PySentinel se enfoca en la detección de comportamiento anómalo en tiempo real, monitorización de la salud del sistema y respuesta interactiva ante amenazas.

El sistema integra vigilancia de **Red**, **Archivos**, **Logs de Windows** y **Dispositivos USB** en un dashboard centralizado con alertas al móvil.

## 📸 Dashboard

*(Sube una captura de tu GUI aquí y pon la ruta, ej: `![Dashboard](screenshots/dashboard.png)`)*

## 🚀 Capacidades (Nivel EDR)

### 1. 🌐 NetWatch Interactivo (Firewall de Aplicación)
* **Monitorización:** Analiza todas las conexiones TCP salientes en tiempo real.
* **Respuesta Activa:** Si un proceso desconocido (fuera de la Whitelist) intenta conectarse a Internet, el sistema **bloquea el hilo de ejecución** y despliega una ventana de alerta segura.
* **Decisión del Usuario:** Permite **BLOQUEAR** (Kill Process) o **PERMITIR** la conexión al instante.
* **Notificaciones Toast:** Avisos nativos de Windows 10/11 no intrusivos.

### 2. 🔌 USB Sentry (Seguridad Física)
* Detección inmediata de dispositivos de almacenamiento conectados ("Hot-plug").
* Alerta crítica sobre nuevos volúmenes montados para prevenir ataques físicos o exfiltración de datos.
* Sistema tolerante a fallos para evitar crasheos por hardware defectuoso.

### 3. 👁️ Windows Event Monitor (Real-Time Logs)
* Integración directa con la **Win32 API** para leer el *Security Event Log* del Kernel.
* Detección proactiva del **Evento ID 4625** (Fallos de inicio de sesión / Fuerza bruta).

### 4. 📂 File Integrity Monitor (FIM)
* Motor de hashing SHA-256 para vigilar cambios no autorizados, creación o eliminación de archivos en directorios críticos.

### 5. 📊 Salud del Sistema & Reporting
* Visualización en tiempo real de CPU, RAM y Disco (`psutil`).
* Exportación de incidentes a **CSV** para auditorías forenses.
* Notificaciones Push al móvil vía **Telegram Bot API**.

## 📦 Instalación

### Prerrequisitos
PySentinel requiere permisos de **Administrador** para interactuar con los logs del sistema y gestionar procesos.

1.  **Clonar el repositorio:**
    ```bash
    git clone [https://github.com/TU_USUARIO/PySentinel.git](https://github.com/TU_USUARIO/PySentinel.git)
    cd PySentinel
    ```

2.  **Instalar dependencias:**
    ```bash
    pip install -r requirements.txt
    ```
    *Librerías clave: `customtkinter`, `psutil`, `pywin32`, `win10toast`, `pyyaml`, `requests`.*

## ⚙️ Configuración (`config.yaml`)

El sistema requiere un archivo `config.yaml` en la raíz. Usa este ejemplo completo:

```yaml
system:
  version: "2.0"
  debug_mode: true

monitoring:
  # Carpetas a vigilar (El sistema añade 'Startup' de Windows automáticamente)
  directories:
    - "./test_folder"
    - "C:/Users/TuUsuario/Documents/Secretos"
  
  # Archivo de logs (Solo para fallback, el sistema usa Win32 API principalmente)
  log_file: "server_logs.txt"

database:
  name: "pysentinel.db"

network:
  # Procesos que pueden conectarse a Internet sin preguntar
  whitelist:
    - "Añadir los tuyos"

security:
  active_response: false  # false = Solo notifica | true = Permite matar procesos

alerts:
  telegram:
    enabled: true
    token: "TU_TOKEN_AQUI"
    chat_id: "TU_ID_AQUI"
```

## 🚀 Ejecución

### Modo Desarrollo (Python)
1. Abrir terminal como Administrador.
2. Ejecutar:
   ```bash
   python gui.py
    ```

### Modo Producción (.exe)
1. Asegúrate de que config.yaml está en la misma carpeta que el .exe.
2. Clic derecho en PySentinel_HIDS.exe.
3. Seleccionar "Ejecutar como administrador".

## 🛠️ Estructura del Proyecto

```text
PySentinel/
├── gui.py                 # Controlador principal (MVC)
├── config.yaml            # Configuración (Ignorado por Git)
├── pysentinel/
│   ├── core/              # Base de datos & Config Loader
│   ├── modules/
│   │   ├── win_event_watcher.py  # API Windows Logs
│   │   ├── network_monitor.py    # EDR NetWatch (ctypes)
│   │   ├── usb_monitor.py        # USB Sentry
│   │   └── fim.py                # File Integrity
│   └── utils/             # Notificaciones, Logger, System Stats
└── ...
```

## 🚢 Despliegue y Distribución

### Opción A: Ejecutable Portable (Windows)
El proyecto puede compilarse en un binario `.exe` independiente que incluye todas las dependencias:
```bash
# Generar el ejecutable
pyinstaller --noconsole --onefile --collect-all customtkinter gui.py
```
El ejecutable resultante en dist/ requiere el archivo config.yaml en la misma carpeta para funcionar.

### Opción B: Docker (Contenedor Linux)
Para entornos aislados o despliegue en servidores, el proyecto incluye configuración Docker:
```bash
# Construir la imagen
docker build -t pysentinel .

# Ejecutar (Requiere servidor X11 configurado para GUI)
docker run -v $(pwd)/config.yaml:/app/config.yaml pysentinel
```




Disclaimer: Este software incluye capacidades de cierre de procesos ("Kill Switch"). Úselo bajo su propia responsabilidad y asegúrese de configurar correctamente la lista blanca (whitelist) para evitar interrupciones en el sistema.

Desarrollado por Álvaro Fernández Ramos - Proyecto de Ingeniería de Ciberseguridad.