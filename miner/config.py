import json
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MinerConfig:
    pool_host: str = "solo.ckpool.org"
    pool_port: int = 3333
    wallet: str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"
    worker: str = "worker1"
    password: str = "x"
    threads: int = max(1, os.cpu_count() - 1)
    log_interval: int = 10  # seconds between hashrate logs

    @classmethod
    def from_file(cls, path: str) -> "MinerConfig":
        with open(path) as f:
            data = json.load(f)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_args(cls, args) -> "MinerConfig":
        cfg = cls()
        if args.config:
            cfg = cls.from_file(args.config)
        for field_name in ("pool_host", "pool_port", "wallet", "worker", "password", "threads"):
            val = getattr(args, field_name, None)
            if val is not None:
                setattr(cfg, field_name, val)
        return cfg

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2)
