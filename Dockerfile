# Usamos Python 3.10 Slim para reducir tamaño y superficie de ataque
FROM python:3.10-slim

# Metadatos
LABEL maintainer="Basilisk Security Team"
LABEL version="6.7.0"
LABEL description="Basilisk EDR - Enterprise C2 Node"

# Variables de entorno para Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# 1. Instalar dependencias del sistema (necesarias para criptografía y compilación)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    libffi-dev \
    libssl-dev \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# 2. Configurar directorio de trabajo
WORKDIR /app

# 3. Copiar dependencias y actualizar pip
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 4. Copiar el código fuente
COPY . .

# 5. Crear usuario no privilegiado para seguridad (Solo usado si no se requieren permisos de root para EDR)
# En el servidor C2 es buena práctica.
RUN useradd -m basilisk_user
RUN chown -R basilisk_user:basilisk_user /app

# 6. Exponer puerto del C2
EXPOSE 8443

# El comando por defecto arranca el servidor, pero se puede sobrescribir
CMD ["python", "server/server.py"]