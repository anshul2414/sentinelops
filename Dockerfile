FROM python:3.12-slim
WORKDIR /srv
COPY backend/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /srv/backend
COPY frontend /srv/frontend
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
WORKDIR /srv/backend
# Bind to the port Render provides ($PORT), falling back to 8000 locally.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
