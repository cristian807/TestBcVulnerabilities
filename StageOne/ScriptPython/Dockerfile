FROM python:3.12-slim

WORKDIR /app

COPY src/ ./src/

RUN pip install --no-cache-dir requests

ENV PYTHONPATH=/app/src

CMD ["python", "src/Presentation/Main.py"]
