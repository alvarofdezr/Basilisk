FROM python:3.10-slim

LABEL maintainer="Basilisk Security Team"
LABEL description="Basilisk EDR Containerized Agent"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Dependencias del sistema para GUI y red
RUN apt-get update && apt-get install -y \
    python3-tk \
    tk-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ejecución por defecto del agente
CMD ["python", "agent/agent_core.py"]