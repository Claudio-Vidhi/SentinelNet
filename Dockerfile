# Usa un'immagine ufficiale Python leggera come base
FROM python:3.11-slim

# Imposta la directory di lavoro all'interno del container
WORKDIR /app

# Installa le dipendenze di sistema richieste (iputils-ping: il 'ping' usato
# da collectors/network_scanner.py) e ripulisce la cache di apt per
# mantenere l'immagine il più leggera possibile.
RUN apt-get update && \
    apt-get install --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Copia prima il file delle dipendenze per sfruttare al meglio la cache dei layer di Docker
COPY requirements.txt .

# Installa le dipendenze Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia l'intero progetto nella directory di lavoro del container
COPY . .

# L'app gira come utente non privilegiato (plan Phase 3, item 16).
# Il bind mount ./data:/app/data deve essere scrivibile da uid 1000:
# su host Linux eseguire 'chown -R 1000:1000 ./data' prima del primo avvio.
RUN useradd --create-home --uid 1000 sentinel && \
    mkdir -p /app/data && \
    chown -R sentinel:sentinel /app
USER sentinel

# Imposta le variabili d'ambiente predefinite per il funzionamento in Docker
ENV PYTHONUNBUFFERED=1 \
    SENTINELNET_HOST=0.0.0.0 \
    SENTINELNET_PORT=8000 \
    SENTINELNET_NO_BROWSER=true \
    SENTINELNET_DATA_DIR=/app/data

# Dichiara la directory dati come volume per la persistenza standalone
VOLUME /app/data

# Espone la porta del server FastAPI
EXPOSE 8000

# Salute del container: l'endpoint /api/version risponde senza autenticazione.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os, sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('SENTINELNET_PORT', '8000') + '/api/version', timeout=4).status == 200 else 1)"

# Comando per avviare l'app FastAPI
CMD ["python", "app_server.py"]
