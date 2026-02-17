FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

# Create non-root user
RUN useradd -r -u 1000 honeypot &&     mkdir -p /app/logs &&     chown -R honeypot:honeypot /app

COPY --chown=honeypot:honeypot app.py .
COPY --chown=honeypot:honeypot templates/ templates/

USER honeypot

EXPOSE 18789

CMD ["gunicorn", "--bind", "0.0.0.0:18789", "--workers", "2", "--access-logfile", "-", "app:app"]
