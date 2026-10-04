FROM python:3.12-slim

WORKDIR /app

# uv for fast installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Dependencies first for layer caching; constraints pin exact versions so a
# rebuild never silently pulls a new major or minor.
COPY requirements.txt constraints.txt /tmp/
RUN uv pip install --system -r /tmp/requirements.txt -c /tmp/constraints.txt

# The skywalker package from the same commit (deploy.sh copies src/skywalker).
# The server only needs skywalker.intel, which uses requests, not the Google SDKs.
COPY skywalker_src/__init__.py /app/skywalker/__init__.py
COPY skywalker_src/intel /app/skywalker/intel

# MCP server code
COPY server.py app.py auth.py access.py users.py store.py cache.py scope.py agent.py /app/

EXPOSE 8080
ENV PYTHONPATH=/app

CMD ["python", "app.py"]
