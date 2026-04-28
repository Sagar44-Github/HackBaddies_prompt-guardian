"""
app.py — Prompt Guardian Flask API

Production-grade REST API for the prompt injection firewall.

Routes:
    GET  /health          -> service health + uptime
    POST /analyze         -> analyse a single prompt
    POST /analyze/batch   -> analyse multiple prompts
    GET  /stats           -> live request statistics
"""

import os
import time
import uuid
import logging
from datetime import datetime, timezone
from collections import defaultdict
from threading import Lock

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
from firewall.analyzer import analyze_prompt

load_dotenv()


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION (overridable via .env)
# ═══════════════════════════════════════════════════════════════════════════════

_API_VERSION       = os.getenv("API_VERSION", "1.0.0")
_HOST              = os.getenv("API_HOST", "127.0.0.1")
_PORT              = int(os.getenv("API_PORT", "5000"))
_DEBUG             = os.getenv("API_DEBUG", "true").lower() == "true"
_MAX_PROMPT_LENGTH = int(os.getenv("MAX_PROMPT_LENGTH", "8000"))
_MAX_BATCH_SIZE    = int(os.getenv("MAX_BATCH_SIZE", "10"))
_RATE_LIMIT        = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))


# ═══════════════════════════════════════════════════════════════════════════════
#  APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("prompt-guardian")

_start_time = time.time()


# ═══════════════════════════════════════════════════════════════════════════════
#  IN-MEMORY STATS TRACKER
# ═══════════════════════════════════════════════════════════════════════════════

class _Stats:
    """Thread-safe request statistics tracker."""

    def __init__(self):
        self._lock = Lock()
        self.total_requests = 0
        self.total_blocked = 0
        self.total_warned = 0
        self.total_allowed = 0
        self.total_errors = 0
        self.attack_types = defaultdict(int)

    def record(self, result: dict):
        with self._lock:
            self.total_requests += 1
            action = result.get("action", "ALLOW")
            if action == "BLOCK":
                self.total_blocked += 1
            elif action == "WARN":
                self.total_warned += 1
            else:
                self.total_allowed += 1
            attack = result.get("attack_type")
            if attack and attack != "Unknown":
                self.attack_types[attack] += 1

    def record_error(self):
        with self._lock:
            self.total_requests += 1
            self.total_errors += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "total_blocked": self.total_blocked,
                "total_warned": self.total_warned,
                "total_allowed": self.total_allowed,
                "total_errors": self.total_errors,
                "attack_types": dict(self.attack_types),
            }


stats = _Stats()


# ═══════════════════════════════════════════════════════════════════════════════
#  SIMPLE IN-MEMORY RATE LIMITER (no extra dependencies)
# ═══════════════════════════════════════════════════════════════════════════════

class _RateLimiter:
    """Per-IP sliding-window rate limiter (1-minute window)."""

    def __init__(self, max_requests: int):
        self._max = max_requests
        self._lock = Lock()
        self._windows = {}          # ip -> list of timestamps

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            timestamps = self._windows.get(ip, [])
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= self._max:
                self._windows[ip] = timestamps
                return False
            timestamps.append(now)
            self._windows[ip] = timestamps
            return True

    def remaining(self, ip: str) -> int:
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            timestamps = self._windows.get(ip, [])
            active = [t for t in timestamps if t > cutoff]
            return max(0, self._max - len(active))


rate_limiter = _RateLimiter(_RATE_LIMIT)


# ═══════════════════════════════════════════════════════════════════════════════
#  MIDDLEWARE (before / after every request)
# ═══════════════════════════════════════════════════════════════════════════════

@app.before_request
def before_request_hook():
    """Attach request ID, start timer, and enforce rate limit."""
    g.request_id = uuid.uuid4().hex[:12]
    g.start_time = time.time()

    # Rate limiting (skip for health check)
    if request.path != "/health":
        client_ip = request.remote_addr or "unknown"
        if not rate_limiter.is_allowed(client_ip):
            logger.warning("Rate limited: ip=%s path=%s", client_ip, request.path)
            return jsonify({
                "error": "Rate limit exceeded ({} requests/minute)".format(_RATE_LIMIT),
            }), 429


@app.after_request
def after_request_hook(response):
    """Log request and add standard headers."""
    elapsed = round((time.time() - g.get("start_time", time.time())) * 1000, 1)

    response.headers["X-Request-Id"] = g.get("request_id", "unknown")
    response.headers["X-Response-Time-Ms"] = str(elapsed)
    response.headers["X-API-Version"] = _API_VERSION

    logger.info(
        "%s %s %s  %sms  ip=%s  req_id=%s",
        request.method,
        request.path,
        response.status_code,
        elapsed,
        request.remote_addr,
        g.get("request_id", "?"),
    )
    return response


# ═══════════════════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(415)
def unsupported_media(e):
    return jsonify({"error": "Content-Type must be application/json"}), 415


@app.errorhandler(429)
def rate_limit_error(e):
    return jsonify({"error": "Rate limit exceeded"}), 429


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  VALIDATION HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def _validate_prompt(data: dict):
    """
    Validate the prompt field from request data.

    Returns:
        (prompt_str, None)     on success
        (None, error_response) on failure
    """
    if not data or "prompt" not in data:
        return None, (jsonify({"error": "Missing 'prompt' field in request body"}), 400)

    raw = data["prompt"]

    if not isinstance(raw, str):
        return None, (jsonify({"error": "Prompt must be a string"}), 400)

    prompt = raw.strip()

    if not prompt:
        return None, (jsonify({"error": "Prompt cannot be empty"}), 400)

    if len(prompt) > _MAX_PROMPT_LENGTH:
        return None, (jsonify({
            "error": "Prompt too long (max {} chars, got {})".format(
                _MAX_PROMPT_LENGTH, len(prompt))
        }), 400)

    return prompt, None


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ── Health Check ──────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Service health check with uptime."""
    uptime_seconds = round(time.time() - _start_time, 1)
    return jsonify({
        "status": "ok",
        "service": "Prompt Guardian API",
        "version": _API_VERSION,
        "uptime_seconds": uptime_seconds,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── Single Prompt Analysis ────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyse a single prompt for injection attacks.

    Expects JSON: {"prompt": "user text here"}
    Returns: full risk scoring result from the firewall analyzer.
    """
    data = request.get_json(silent=True)

    prompt, error = _validate_prompt(data)
    if error:
        return error

    try:
        start = time.time()
        result = analyze_prompt(prompt)
        result["analysis_time_ms"] = round((time.time() - start) * 1000, 1)
        result["request_id"] = g.get("request_id", "unknown")
        stats.record(result)
    except Exception as e:
        stats.record_error()
        logger.error("Analysis failed: %s", str(e), exc_info=True)
        return jsonify({"error": "Analysis failed: {}".format(str(e))}), 500

    return jsonify(result)


# ── Batch Prompt Analysis ─────────────────────────────────────────────────────

@app.route("/analyze/batch", methods=["POST"])
def analyze_batch():
    """
    Analyse multiple prompts in a single request.

    Expects JSON: {"prompts": ["text1", "text2", ...]}
    Returns: {"results": [...], "summary": {...}}
    Max batch size is controlled by MAX_BATCH_SIZE (default 10).
    """
    data = request.get_json(silent=True)

    if not data or "prompts" not in data:
        return jsonify({"error": "Missing 'prompts' field in request body"}), 400

    prompts = data["prompts"]

    if not isinstance(prompts, list):
        return jsonify({"error": "'prompts' must be a list of strings"}), 400

    if len(prompts) == 0:
        return jsonify({"error": "Prompts list cannot be empty"}), 400

    if len(prompts) > _MAX_BATCH_SIZE:
        return jsonify({
            "error": "Batch too large (max {} prompts, got {})".format(
                _MAX_BATCH_SIZE, len(prompts))
        }), 400

    results = []
    batch_start = time.time()
    blocked = 0
    warned = 0
    allowed = 0

    for i, raw_prompt in enumerate(prompts):
        if not isinstance(raw_prompt, str) or not raw_prompt.strip():
            results.append({
                "index": i,
                "error": "Invalid or empty prompt at index {}".format(i),
            })
            continue

        prompt = raw_prompt.strip()
        if len(prompt) > _MAX_PROMPT_LENGTH:
            results.append({
                "index": i,
                "error": "Prompt at index {} exceeds max length".format(i),
            })
            continue

        try:
            result = analyze_prompt(prompt)
            result["index"] = i
            stats.record(result)

            action = result.get("action", "ALLOW")
            if action == "BLOCK":
                blocked += 1
            elif action == "WARN":
                warned += 1
            else:
                allowed += 1

            results.append(result)
        except Exception as e:
            stats.record_error()
            results.append({
                "index": i,
                "error": "Analysis failed: {}".format(str(e)),
            })

    batch_time = round((time.time() - batch_start) * 1000, 1)

    return jsonify({
        "results": results,
        "summary": {
            "total": len(prompts),
            "blocked": blocked,
            "warned": warned,
            "allowed": allowed,
            "batch_time_ms": batch_time,
        },
        "request_id": g.get("request_id", "unknown"),
    })


# ── Live Statistics ───────────────────────────────────────────────────────────

@app.route("/stats", methods=["GET"])
def get_stats():
    """Return live request statistics since server start."""
    data = stats.snapshot()
    data["uptime_seconds"] = round(time.time() - _start_time, 1)
    return jsonify(data)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("  Prompt Guardian API")
    print("  Version:    {}".format(_API_VERSION))
    print("  Host:       {}:{}".format(_HOST, _PORT))
    print("  Debug:      {}".format(_DEBUG))
    print("  Max prompt: {} chars".format(_MAX_PROMPT_LENGTH))
    print("  Max batch:  {} prompts".format(_MAX_BATCH_SIZE))
    print("  Rate limit: {} req/min".format(_RATE_LIMIT))
    print("=" * 55)
    app.run(host=_HOST, port=_PORT, debug=_DEBUG)
