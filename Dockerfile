FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi[standard] cryptography

COPY . .

EXPOSE 7002

ENTRYPOINT ["uvicorn", "__init__:app", "--host", "0.0.0.0", "--port", "7002"]
