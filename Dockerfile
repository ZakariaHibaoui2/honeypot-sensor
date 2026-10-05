FROM python:3.12-slim
RUN useradd --create-home honeytrap
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && mkdir /logs && chown honeytrap /logs
USER honeytrap
EXPOSE 2222 2323 2121 8080
CMD ["honeytrap", "run", "--host", "0.0.0.0", "--log", "/logs/honeytrap.jsonl"]
