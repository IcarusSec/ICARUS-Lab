FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
# Dummy key file for /api/protected/kid path-traversal demo
RUN mkdir -p /app/keys && echo -n "secret" > /app/keys/default
EXPOSE 5000
CMD ["python", "app.py"]
