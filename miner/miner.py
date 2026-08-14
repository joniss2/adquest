"""Haupt-Miner-Logik: koordiniert Pool-Verbindung und Worker-Prozesse."""
import logging
import multiprocessing as mp
import threading
import time

from .config import MinerConfig
from .stratum import StratumClient
from .worker import MinerStats, MiningWorker

logger = logging.getLogger(__name__)


class Miner:
    def __init__(self, config: MinerConfig) -> None:
        self.config = config
        self._hash_counter: mp.Value = mp.Value("Q", 0)
        self._share_queue: mp.Queue = mp.Queue()
        self._job_queues: list[mp.Queue] = []
        self._workers: list[MiningWorker] = []
        self._client: StratumClient | None = None
        self._running = False
        self._reconnect_delay = 5
        self.stats: MinerStats | None = None

    # ------------------------------------------------------------------ public

    def start(self) -> None:
        self._running = True
        self.stats = MinerStats(self._hash_counter)
        self._spawn_workers()
        threading.Thread(target=self._share_consumer, daemon=True).start()
        self._connect_loop()

    def stop(self) -> None:
        logger.info("Stoppe Miner...")
        self._running = False
        for q in self._job_queues:
            try:
                q.put_nowait(None)
            except Exception:
                pass
        for w in self._workers:
            w.stop()
        if self._client:
            self._client.disconnect()

    # --------------------------------------------------------------- internals

    def _spawn_workers(self) -> None:
        n = self.config.threads
        logger.info("Starte %d Worker-Prozess(e)", n)
        for i in range(n):
            q: mp.Queue = mp.Queue(maxsize=2)
            self._job_queues.append(q)
            w = MiningWorker(i, n, q, self._share_queue, self._hash_counter)
            w.start()
            self._workers.append(w)

    def _connect_loop(self) -> None:
        delay = self._reconnect_delay
        while self._running:
            logger.info("Verbinde mit %s:%d ...", self.config.pool_host, self.config.pool_port)
            client = StratumClient(
                self.config.pool_host,
                self.config.pool_port,
                on_job=self._on_job,
                on_disconnect=lambda: None,
            )
            self._client = client

            if not client.connect():
                logger.warning("Verbindung fehlgeschlagen, neuer Versuch in %ds", delay)
                time.sleep(delay)
                delay = min(delay * 2, 60)
                continue

            if not client.subscribe():
                logger.warning("Subscribe fehlgeschlagen")
                client.disconnect()
                time.sleep(delay)
                continue

            if not client.authorize(self.config.wallet, self.config.worker, self.config.password):
                logger.warning("Authorize fehlgeschlagen")
                client.disconnect()
                time.sleep(delay)
                continue

            delay = self._reconnect_delay

            threading.Thread(target=self._report_loop, daemon=True).start()

            while self._running and client._running:
                time.sleep(1)

            if self._running:
                logger.warning("Verbindung verloren, neuer Versuch in %ds", delay)
                time.sleep(delay)

    def _on_job(self, job: dict) -> None:
        action = "Neuer Job" if job.get("clean_jobs") else "Job-Update"
        logger.info("%s: %s  Schwierigkeit: %.4f", action, job["job_id"], self._client.difficulty)
        item = (job, self._client.extra_nonce1, self._client.extra_nonce2_size)
        for q in self._job_queues:
            # Alten Job rauswerfen, neuen rein
            while not q.empty():
                try:
                    q.get_nowait()
                except Exception:
                    break
            try:
                q.put_nowait(item)
            except Exception:
                pass

    def _share_consumer(self) -> None:
        while self._running:
            try:
                job_id, extra_nonce2, ntime, nonce = self._share_queue.get(timeout=1)
            except Exception:
                continue
            if not self._client:
                continue
            username = f"{self.config.wallet}.{self.config.worker}"
            ok = self._client.submit(username, job_id, extra_nonce2, ntime, nonce)
            self.stats.record_share()
            status = "akzeptiert" if ok else "abgelehnt"
            logger.info("Share %s  |  Gesamt: %d", status, self.stats.report()["shares"])

    def _report_loop(self) -> None:
        while self._running and self._client and self._client._running:
            time.sleep(self.config.log_interval)
            r = self.stats.report()
            logger.info(
                "Hashrate: %s  |  Shares: %d  |  Laufzeit: %.0fs",
                self.stats.hashrate_str(),
                r["shares"],
                r["elapsed"],
            )
