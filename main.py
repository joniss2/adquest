#!/usr/bin/env python3
"""SHA-256 CPU Krypto-Miner — Stratum-kompatibel."""
import argparse
import logging
import signal
import sys

from miner.config import MinerConfig
from miner.miner import Miner


def main() -> None:
    parser = argparse.ArgumentParser(description="SHA-256 CPU-Miner (Stratum v1)")
    parser.add_argument("-c", "--config", metavar="FILE", help="JSON-Konfigurationsdatei")
    parser.add_argument("--pool-host", metavar="HOST", help="Pool-Hostname (Standard: solo.ckpool.org)")
    parser.add_argument("--pool-port", metavar="PORT", type=int, help="Pool-Port (Standard: 3333)")
    parser.add_argument("--wallet", metavar="ADDR", help="Bitcoin-Wallet-Adresse")
    parser.add_argument("--worker", metavar="NAME", help="Worker-Name (Standard: worker1)")
    parser.add_argument("--password", metavar="PASS", default=None, help="Worker-Passwort")
    parser.add_argument("--threads", metavar="N", type=int, help="Anzahl Miner-Threads")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Log-Level (Standard: INFO)")
    parser.add_argument("--save-config", metavar="FILE",
                        help="Aktuelle Konfiguration in Datei speichern und beenden")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    config = MinerConfig.from_args(args)

    if args.save_config:
        config.save(args.save_config)
        print(f"Konfiguration gespeichert: {args.save_config}")
        sys.exit(0)

    miner = Miner(config)

    def _shutdown(sig, frame):
        print()
        miner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print("=" * 60)
    print("  SHA-256 CPU-Miner")
    print(f"  Pool:    {config.pool_host}:{config.pool_port}")
    print(f"  Wallet:  {config.wallet}")
    print(f"  Worker:  {config.worker}")
    print(f"  Threads: {config.threads}")
    print("=" * 60)
    print("  Strg+C zum Beenden")
    print()

    miner.start()


if __name__ == "__main__":
    main()
