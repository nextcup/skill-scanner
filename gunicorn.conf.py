# Gunicorn configuration for Skill Scanner API
# Production settings with Uvicorn workers for FastAPI

import multiprocessing
import os

# ── Server Socket ─────────────────────────────────────────────────────────────

bind = "0.0.0.0:8000"
backlog = 2048

# ── Worker Processes ───────────────────────────────────────────────────────────

# Number of worker processes (default: CPU cores * 2 + 1)
workers = int(os.getenv("SKILL_SCANNER_WORKERS", multiprocessing.cpu_count() * 2 + 1))

# Worker class for FastAPI (ASGI)
worker_class = "uvicorn.workers.UvicornWorker"

# Worker connections
worker_connections = 1000

# Max requests per worker (prevent memory leaks)
max_requests = 1000
max_requests_jitter = 100

# ── Timeout Settings ────────────────────────────────────────────────────────────

timeout = 120
keepalive = 5
graceful_timeout = 30

# ── Process Naming ─────────────────────────────────────────────────────────────

proc_name = "skill-scanner"

# ── Logging ────────────────────────────────────────────────────────────────────

accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")

# Access log format with request timing
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'
)

# ── App Loading ────────────────────────────────────────────────────────────────

# Preload app (faster worker spawn, but uses more memory)
preload_app = False

# ── Server Hooks ───────────────────────────────────────────────────────────────

def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting Skill Scanner API server")


def when_ready(server):
    """Called just after the server is started."""
    server.log.info(
        f"Skill Scanner API server is ready. "
        f"Listening on {bind} with {workers} workers"
    )


def on_exit(server):
    """Called just before exiting the master process."""
    server.log.info("Shutting down Skill Scanner API server")


def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info(f"Worker received INT or QUIT signal (pid: {worker.pid})")


def pre_fork(server, worker):
    """Called just before a worker is forked."""
    pass


def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info(
        f"Worker spawned (pid: {worker.pid}, ppid: {worker.pid})"
    )


def pre_exec(server):
    """Called just before a new master process is forked."""
    server.log.info("Forked child, re-executing.")


def worker_abort(worker):
    """Called when a worker received the SIGABRT signal."""
    worker.log.info(f"Worker received SIGABRT signal (pid: {worker.pid})")
