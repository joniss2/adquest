"""Mining-Worker: Proof-of-Work per SHA-256 (Bitcoin-kompatibel)."""
import hashlib
import multiprocessing as mp
import struct
import time
import logging
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# Größeres Batch = weniger Python-Overhead pro Hash
BATCH_SIZE = 262144


# ---------------------------------------------------------------------------
# Reine Hilfsfunktionen (pickleable, testbar)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Interne Hilfsfunktionen für Worker-Prozesse
# ---------------------------------------------------------------------------

def _build_merkle(job: dict, extra_nonce1: str, en2_int: int, en2_size: int):
    en2_hex = le_hex(en2_int, en2_size)
    cb = build_coinbase(job["coinbase1"], extra_nonce1, en2_hex, job["coinbase2"])
    root = build_merkle_root(double_sha256(cb), job["merkle_branch"])
    return root, en2_hex


def _make_prefix(job: dict, merkle_root: bytes) -> bytes:
    """Baut die 76-Byte-Prefix des Block-Headers (alles außer dem Nonce)."""
    return (
        struct.pack("<I", int(job["version"], 16))
        + bytes.fromhex(job["prev_hash"])
        + merkle_root
        + struct.pack("<I", int(job["ntime"], 16))
        + struct.pack("<I", int(job["nbits"], 16))
    )


def _worker_process(worker_id: int, num_workers: int,
                    job_queue: mp.Queue, share_queue: mp.Queue,
                    hash_counter: mp.Value) -> None:
    """Einstiegspunkt für Worker-Subprozesse (muss pickleable sein)."""
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s  Worker-{worker_id}  %(levelname)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    item = job_queue.get()
    while item is not None:
        job, extra_nonce1, en2_size = item
        item = _mine_loop(worker_id, num_workers, job, extra_nonce1, en2_size,
                          job_queue, share_queue, hash_counter)


def _mine_loop(worker_id: int, num_workers: int, job: dict,
               extra_nonce1: str, en2_size: int,
               job_queue: mp.Queue, share_queue: mp.Queue,
               hash_counter: mp.Value) -> Optional[tuple]:
    """
    Hauptschleife: SHA-256-Double-Hash mit drei Optimierungen:

    1. Midstate: Der Header ist 80 Byte. SHA-256 verarbeitet 64-Byte-Blöcke.
       Die ersten 64 Byte (version + prev_hash + merkle_root[0:28]) ändern
       sich pro en2-Wert nicht. Der SHA-256-Zustand nach diesen 64 Byte wird
       einmal berechnet und dann nur noch per copy() geklont — spart eine
       vollständige 64-Byte-Block-Verarbeitung pro Hash (~33 % schneller).

    2. bytearray-Nonce-Buffer: Vermeidet Speicherallokation im Hot-Loop.
       struct.pack_into schreibt direkt in den bestehenden Buffer.

    3. Größeres Batch (262144): Weniger Python-Overhead pro Hash durch
       seltene Queue-Checks und Lock-Acquires.

    Gibt das nächste Job-Tupel zurück (oder None zum Stoppen).
    """
    target = bits_to_target(job["nbits"])
    en2_int = worker_id
    stride = num_workers

    merkle_root, extra_nonce2 = _build_merkle(job, extra_nonce1, en2_int, en2_size)
    prefix = _make_prefix(job, merkle_root)

    # Midstate: SHA-256-Zustand nach den ersten 64 statischen Bytes
    midstate = hashlib.sha256()
    midstate.update(prefix[:64])

    # nonce_frame: bytes 64–75 (statisch) + bytes 76–79 (Nonce, variabel)
    nonce_frame = bytearray(16)
    nonce_frame[:12] = prefix[64:]

    nonce = 0
    job_id = job["job_id"]
    ntime = job["ntime"]

    while True:
        if nonce > 0xFFFFFFFF:
            nonce = 0
            en2_int += stride
            merkle_root, extra_nonce2 = _build_merkle(job, extra_nonce1, en2_int, en2_size)
            prefix = _make_prefix(job, merkle_root)
            midstate = hashlib.sha256()
            midstate.update(prefix[:64])
            nonce_frame[:12] = prefix[64:]

        local_hashes = 0
        for _ in range(BATCH_SIZE):
            if nonce > 0xFFFFFFFF:
                break

            # Nonce in den letzten 4 Byte des Frames schreiben (keine Allokation)
            struct.pack_into("<I", nonce_frame, 12, nonce)

            # SHA-256: Midstate klonen + restliche 16 Byte verarbeiten
            h = midstate.copy()
            h.update(nonce_frame)
            hash_val = hashlib.sha256(h.digest()).digest()

            if int.from_bytes(hash_val[::-1], "big") < target:
                logger.info("Worker %d: Share! Nonce=%08x", worker_id, nonce)
                share_queue.put((job_id, extra_nonce2, ntime, f"{nonce:08x}"))

            nonce += 1
            local_hashes += 1

        with hash_counter.get_lock():
            hash_counter.value += local_hashes

        try:
            return job_queue.get_nowait()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Öffentliche API
# ---------------------------------------------------------------------------

class MiningWorker:
    """Verwaltet einen Worker-Subprozess."""

    def __init__(self, worker_id: int, num_workers: int,
                 job_queue: mp.Queue, share_queue: mp.Queue,
                 hash_counter: mp.Value):
        self.worker_id = worker_id
        self._process = mp.Process(
            target=_worker_process,
            args=(worker_id, num_workers, job_queue, share_queue, hash_counter),
            daemon=True,
            name=f"Worker-{worker_id}",
        )

    def start(self) -> None:
        self._process.start()

    def stop(self) -> None:
        self._process.terminate()

    def is_alive(self) -> bool:
        return self._process.is_alive()


class MinerStats:
    """Hashrate- und Share-Statistiken für den Haupt-Prozess."""

    def __init__(self, hash_counter: mp.Value) -> None:
        self._hash_counter = hash_counter
        self._lock = __import__("threading").Lock()
        self._shares = 0
        self._start = time.monotonic()

    def record_share(self) -> None:
        with self._lock:
            self._shares += 1

    def report(self) -> dict:
        elapsed = time.monotonic() - self._start
        with self._hash_counter.get_lock():
            total = self._hash_counter.value
        hashrate = total / elapsed if elapsed > 0 else 0
        with self._lock:
            shares = self._shares
        return {"hashrate": hashrate, "total_hashes": total, "shares": shares, "elapsed": elapsed}

    def hashrate_str(self) -> str:
        hr = self.report()["hashrate"]
        if hr >= 1e9:
            return f"{hr/1e9:.2f} GH/s"
        if hr >= 1e6:
            return f"{hr/1e6:.2f} MH/s"
        if hr >= 1e3:
            return f"{hr/1e3:.2f} KH/s"
        return f"{hr:.0f} H/s"
