FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY ui /app/ui
RUN pip install --no-cache-dir --timeout 120 --retries 10 -e .
EXPOSE 8000
CMD ["uvicorn", "rbcollector.server:app", "--host", "0.0.0.0", "--port", "8000"]
