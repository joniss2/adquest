"""Haupt-Miner-Logik: koordiniert Pool-Verbindung und Worker-Threads."""
import logging
import threading
import time

from .config import MinerConfig
from .stratum import StratumClient
from .worker import MinerStats, MiningWorker

logger = logging.getLogger(__name__)


class Miner:
    def __init__(self, config: MinerConfig) -> None:
        self.config = config
        self.stats = MinerStats()
        self._workers: list[MiningWorker] = []
        self._client: StratumClient | None = None
        self._running = False
        self._reconnect_delay = 5

    # ------------------------------------------------------------------ public

    def start(self) -> None:
        self._running = True
        self._spawn_workers()
        self._connect_loop()

    def stop(self) -> None:
        logger.info("Stoppe Miner...")
        self._running = False
        for w in self._workers:
            w.stop()
        if self._client:
            self._client.disconnect()

    # --------------------------------------------------------------- internals

    def _spawn_workers(self) -> None:
        n = self.config.threads
        logger.info("Starte %d Worker-Thread(s)", n)
        for i in range(n):
            w = MiningWorker(i, self.stats)
            w.on_share_found = self._on_share_found
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

            delay = self._reconnect_delay  # Reset nach Erfolg

            # Hashrate-Reporting
            reporter = threading.Thread(target=self._report_loop, daemon=True)
            reporter.start()

            # Warte bis die Verbindung abbricht
            while self._running and client._running:
                time.sleep(1)

            if self._running:
                logger.warning("Verbindung verloren, neuer Versuch in %ds", delay)
                time.sleep(delay)

    def _on_job(self, job: dict) -> None:
        action = "Neuer Job" if job.get("clean_jobs") else "Job-Update"
        logger.info("%s: %s  Schwierigkeit: %.4f", action, job["job_id"], self._client.difficulty)
        for w in self._workers:
            w.set_job(job, self._client.extra_nonce1, self._client.extra_nonce2_size)

    def _on_share_found(self, job_id: str, extra_nonce2: str, ntime: str, nonce: str) -> None:
        if not self._client:
            return
        username = f"{self.config.wallet}.{self.config.worker}"
        ok = self._client.submit(username, job_id, extra_nonce2, ntime, nonce)
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
