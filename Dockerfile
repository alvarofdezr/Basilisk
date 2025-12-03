# 1. Usamos una imagen base de Python ligera (Linux Debian)
FROM python:3.10-slim

# 2. Metadatos del ingeniero (Tú)
LABEL maintainer="Tu Nombre <tu@email.com>"
LABEL description="basilisk HIDS Container"

# 3. Evitamos que Python genere archivos .pyc y buffer de salida
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 4. Instalamos dependencias del sistema necesarias para la GUI (Tkinter)
# Esto es vital porque las imágenes 'slim' no traen librerías gráficas
RUN apt-get update && apt-get install -y \
    python3-tk \
    tk-dev \
    && rm -rf /var/lib/apt/lists/*

# 5. Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# 6. Copiamos y e instalamos las dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 7. Copiamos el resto del código
COPY . .

# 8. Comando por defecto al iniciar el contenedor
# Nota: Para ver la GUI desde Docker se requiere configuración extra de X11,
# pero este comando deja el contenedor listo para ejecutarse.
CMD ["python", "gui.py"]