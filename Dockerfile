FROM python:3.10-slim

# Metadatos
LABEL maintainer="Basilisk Security Team"
LABEL version="6.7.0"
LABEL description="Basilisk EDR - Enterprise C2 Node"


ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    libffi-dev \
    libssl-dev \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m basilisk_user
RUN chown -R basilisk_user:basilisk_user /app

EXPOSE 8443

CMD ["python", "server/server.py"]