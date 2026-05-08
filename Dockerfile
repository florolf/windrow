FROM golang:1.24-alpine AS sigsum
RUN go install sigsum.org/sigsum-go/cmd/sigsum-submit@v0.14.0

FROM python:3.14-slim

COPY --from=sigsum /go/bin/sigsum-submit /usr/local/bin/sigsum-submit
COPY --from=ghcr.io/astral-sh/uv:0.11.11 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-install-project

COPY __init__.py app.py utils.py /app/windrow/

ENV PATH=/app/.venv/bin:$PATH

EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "windrow.app:create_app()"]
