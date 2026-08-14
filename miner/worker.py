"""Mining-Worker: Proof-of-Work per SHA-256 (Bitcoin-kompatibel)."""
import hashlib
import struct
import threading
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Anzahl Hashes zwischen zwei Nonce-Überprüfungen
BATCH_SIZE = 65536


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def bits_to_target(nbits_hex: str) -> int:
    nbits = int(nbits_hex, 16)
    exponent = nbits >> 24
    mantissa = nbits & 0xFFFFFF
    return mantissa * (1 << (8 * (exponent - 3)))


def build_coinbase(coinbase1: str, extra_nonce1: str, extra_nonce2: str, coinbase2: str) -> bytes:
    return bytes.fromhex(coinbase1 + extra_nonce1 + extra_nonce2 + coinbase2)


def build_merkle_root(coinbase_hash: bytes, merkle_branch: list[str]) -> bytes:
    root = coinbase_hash
    for branch in merkle_branch:
        root = double_sha256(root + bytes.fromhex(branch))
    return root


def build_header(version: str, prev_hash: str, merkle_root: bytes,
                 ntime: str, nbits: str, nonce: int) -> bytes:
    return (
        struct.pack("<I", int(version, 16))
        + bytes.fromhex(prev_hash)
        + merkle_root
        + struct.pack("<I", int(ntime, 16))
        + struct.pack("<I", int(nbits, 16))
        + struct.pack("<I", nonce)
    )


def le_hex(n: int, width: int) -> str:
    return n.to_bytes(width, "little").hex()


class MiningWorker(threading.Thread):
    def __init__(self, worker_id: int, stats: "MinerStats"):
        super().__init__(daemon=True, name=f"Worker-{worker_id}")
        self.worker_id = worker_id
        self.stats = stats

        self._job: Optional[dict] = None
        self._job_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._new_job_event = threading.Event()
        self.on_share_found: Optional[callable] = None

    def set_job(self, job: dict, extra_nonce1: str, extra_nonce2_size: int) -> None:
        with self._job_lock:
            self._job = job
            self._extra_nonce1 = extra_nonce1
            self._extra_nonce2_size = extra_nonce2_size
        self._new_job_event.set()

    def stop(self) -> None:
        self._stop_event.set()
        self._new_job_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            self._new_job_event.wait()
            self._new_job_event.clear()
            if self._stop_event.is_set():
                break
            with self._job_lock:
                job = self._job
                extra_nonce1 = self._extra_nonce1
                extra_nonce2_size = self._extra_nonce2_size
            if job:
                self._mine(job, extra_nonce1, extra_nonce2_size)

    def _mine(self, job: dict, extra_nonce1: str, extra_nonce2_size: int) -> None:
        target = bits_to_target(job["nbits"])

        # Extra-Nonce2 enthält Worker-ID, um Nonce-Überlappung zwischen Workern zu vermeiden
        en2_int = self.worker_id
        extra_nonce2 = le_hex(en2_int, extra_nonce2_size)

        coinbase = build_coinbase(job["coinbase1"], extra_nonce1, extra_nonce2, job["coinbase2"])
        coinbase_hash = double_sha256(coinbase)
        merkle_root = build_merkle_root(coinbase_hash, job["merkle_branch"])

        ntime = job["ntime"]
        version = job["version"]
        nbits = job["nbits"]
        prev_hash = job["prev_hash"]
        job_id = job["job_id"]

        nonce = 0
        start_time = time.monotonic()

        while not self._new_job_event.is_set() and not self._stop_event.is_set():
            # Batch verarbeiten
            for _ in range(BATCH_SIZE):
                if nonce > 0xFFFFFFFF:
                    nonce = 0
                    en2_int += 1
                    extra_nonce2 = le_hex(en2_int, extra_nonce2_size)
                    coinbase = build_coinbase(job["coinbase1"], extra_nonce1, extra_nonce2, job["coinbase2"])
                    coinbase_hash = double_sha256(coinbase)
                    merkle_root = build_merkle_root(coinbase_hash, job["merkle_branch"])

                header = build_header(version, prev_hash, merkle_root, ntime, nbits, nonce)
                hash_val = double_sha256(header)
                hash_int = int.from_bytes(hash_val[::-1], "big")

                if hash_int < target:
                    logger.info(
                        "Worker %d: Share gefunden! Nonce=%08x Hash=%s",
                        self.worker_id, nonce, hash_val[::-1].hex()
                    )
                    if self.on_share_found:
                        self.on_share_found(job_id, extra_nonce2, ntime, f"{nonce:08x}")
                    self.stats.record_share()

                nonce += 1

            self.stats.add_hashes(BATCH_SIZE)


class MinerStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hashes = 0
        self._shares = 0
        self._start = time.monotonic()
        self._last_report = self._start

    def add_hashes(self, n: int) -> None:
        with self._lock:
            self._hashes += n

    def record_share(self) -> None:
        with self._lock:
            self._shares += 1

    def report(self) -> dict:
        with self._lock:
            elapsed = time.monotonic() - self._start
            hashrate = self._hashes / elapsed if elapsed > 0 else 0
            return {
                "hashrate": hashrate,
                "total_hashes": self._hashes,
                "shares": self._shares,
                "elapsed": elapsed,
            }

    def hashrate_str(self) -> str:
        r = self.report()
        hr = r["hashrate"]
        if hr >= 1e9:
            return f"{hr/1e9:.2f} GH/s"
        if hr >= 1e6:
            return f"{hr/1e6:.2f} MH/s"
        if hr >= 1e3:
            return f"{hr/1e3:.2f} KH/s"
        return f"{hr:.0f} H/s"
