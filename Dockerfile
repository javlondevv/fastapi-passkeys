# Runnable demo of examples/app.py: register and sign in with a real passkey.
#
#   docker build -t fastapi-passkeys-demo .
#   docker run --rm -p 8000:8000 fastapi-passkeys-demo
#
# Then open http://localhost:8000. The demo's RP ID / origin are fixed to
# localhost:8000, so publish the container on host port 8000.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install the library from this checkout, plus the ASGI server the demo needs.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . "uvicorn>=0.29" && rm -rf src

COPY examples ./examples

RUN useradd --create-home --uid 10001 --user-group app
USER app

EXPOSE 8000

CMD ["uvicorn", "examples.app:app", "--host", "0.0.0.0", "--port", "8000"]
