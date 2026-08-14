"""Stratum v1 pool client."""
import json
import socket
import threading
import time
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class StratumClient:
    def __init__(self, host: str, port: int, on_job: Callable, on_disconnect: Callable):
        self.host = host
        self.port = port
        self.on_job = on_job
        self.on_disconnect = on_disconnect

        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._req_id = 0
        self._pending: dict[int, threading.Event] = {}
        self._results: dict[int, dict] = {}
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False

        # Mining state
        self.extra_nonce1: str = ""
        self.extra_nonce2_size: int = 4
        self.current_job: Optional[dict] = None
        self.difficulty: float = 1.0

    # ------------------------------------------------------------------ connect

    def connect(self) -> bool:
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=30)
            self._sock.settimeout(None)
            self._running = True
            self._reader_thread = threading.Thread(target=self._reader, daemon=True)
            self._reader_thread.start()
            return True
        except OSError as exc:
            logger.error("Verbindung zu %s:%d fehlgeschlagen: %s", self.host, self.port, exc)
            return False

    def disconnect(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------- send / recv

    def _next_id(self) -> int:
        with self._lock:
            self._req_id += 1
            return self._req_id

    def _send(self, obj: dict) -> None:
        data = json.dumps(obj) + "\n"
        with self._lock:
            self._sock.sendall(data.encode())

    def _call(self, method: str, params: list, timeout: float = 30.0) -> Optional[dict]:
        req_id = self._next_id()
        ev = threading.Event()
        self._pending[req_id] = ev
        self._send({"id": req_id, "method": method, "params": params})
        if not ev.wait(timeout):
            logger.warning("Timeout bei %s", method)
            return None
        return self._results.pop(req_id, None)

    def _reader(self) -> None:
        buf = b""
        while self._running:
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    msg = json.loads(line.decode())
                except json.JSONDecodeError:
                    continue
                self._dispatch(msg)

        self._running = False
        self.on_disconnect()

    def _dispatch(self, msg: dict) -> None:
        # Response to our request
        if msg.get("id") is not None and msg["id"] in self._pending:
            req_id = msg["id"]
            self._results[req_id] = msg
            self._pending.pop(req_id).set()
            return

        # Server notification (id == None)
        method = msg.get("method", "")
        params = msg.get("params", [])

        if method == "mining.notify":
            self._handle_notify(params)
        elif method == "mining.set_difficulty":
            self._handle_difficulty(params)

    def _handle_difficulty(self, params: list) -> None:
        if params:
            self.difficulty = float(params[0])
            logger.info("Schwierigkeit: %.4f", self.difficulty)

    def _handle_notify(self, params: list) -> None:
        if len(params) < 9:
            return
        job = {
            "job_id":       params[0],
            "prev_hash":    params[1],
            "coinbase1":    params[2],
            "coinbase2":    params[3],
            "merkle_branch": params[4],
            "version":      params[5],
            "nbits":        params[6],
            "ntime":        params[7],
            "clean_jobs":   params[8],
        }
        self.current_job = job
        self.on_job(job)

    # ---------------------------------------------------------------- protocol

    def subscribe(self) -> bool:
        resp = self._call("mining.subscribe", ["python-miner/1.0", None])
        if not resp or resp.get("error"):
            return False
        result = resp.get("result", [])
        if len(result) >= 2:
            self.extra_nonce1 = result[1]
            self.extra_nonce2_size = result[2] if len(result) > 2 else 4
        logger.info("Extra-Nonce1: %s  Extra-Nonce2-Größe: %d", self.extra_nonce1, self.extra_nonce2_size)
        return True

    def authorize(self, wallet: str, worker: str, password: str) -> bool:
        username = f"{wallet}.{worker}"
        resp = self._call("mining.authorize", [username, password])
        if not resp:
            return False
        if resp.get("error"):
            logger.error("Authentifizierung fehlgeschlagen: %s", resp["error"])
            return False
        logger.info("Authentifiziert als %s", username)
        return True

    def submit(self, worker: str, job_id: str, extra_nonce2: str, ntime: str, nonce: str) -> bool:
        username = worker
        resp = self._call("mining.submit", [username, job_id, extra_nonce2, ntime, nonce])
        if not resp:
            return False
        if resp.get("error"):
            logger.warning("Share abgelehnt: %s", resp["error"])
            return False
        return True
