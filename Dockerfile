# Usa un'immagine ufficiale Python leggera come base
FROM python:3.11-slim

# Imposta la directory di lavoro all'interno del container
WORKDIR /app

# Installa le dipendenze di sistema richieste (es. iputils-ping per ping3)
# e ripulisce la cache di apt per mantenere l'immagine il più leggera possibile
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Copia prima il file delle dipendenze per sfruttare al meglio la cache dei layer di Docker
COPY requirements.txt .

# Installa le dipendenze Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia l'intero progetto nella directory di lavoro del container
COPY . .

# Imposta le variabili d'ambiente predefinite per il funzionamento in Docker
ENV PYTHONUNBUFFERED=1 \
    SENTINELNET_HOST=0.0.0.0 \
    SENTINELNET_PORT=8765 \
    SENTINELNET_NO_BROWSER=true

# Espone la porta del server FastAPI
EXPOSE 8765

# Comando per avviare l'applicazione
CMD ["python", "app_server.py"]
