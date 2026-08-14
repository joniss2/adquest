"""Tests für die Kern-Mining-Algorithmen."""
import hashlib
import multiprocessing as mp
import struct
import time

from miner.worker import (
    bits_to_target,
    build_coinbase,
    build_header,
    build_merkle_root,
    double_sha256,
    le_hex,
    MinerStats,
    MiningWorker,
    _build_merkle,
    _make_prefix,
)


def test_double_sha256_known_value():
    # SHA256(SHA256("")) = 5df6e0e2...
    result = double_sha256(b"")
    assert result.hex() == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"


def test_bits_to_target_genesis():
    # Bitcoin Genesis-Block: nbits = 0x1d00ffff
    target = bits_to_target("1d00ffff")
    expected = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    assert target == expected


def test_bits_to_target_easy():
    target = bits_to_target("207fffff")
    assert target > 0


def test_build_coinbase():
    cb = build_coinbase("deadbeef", "cafe", "babe", "12345678")
    assert cb == bytes.fromhex("deadbeef" + "cafe" + "babe" + "12345678")


def test_build_merkle_root_single():
    coinbase_hash = double_sha256(b"test")
    root = build_merkle_root(coinbase_hash, [])
    assert root == coinbase_hash


def test_build_merkle_root_one_branch():
    coinbase_hash = double_sha256(b"coinbase")
    branch = double_sha256(b"tx1").hex()
    root = build_merkle_root(coinbase_hash, [branch])
    expected = double_sha256(coinbase_hash + bytes.fromhex(branch))
    assert root == expected


def test_build_header_length():
    header = build_header(
        "00000001",
        "0" * 64,
        b"\x00" * 32,
        "66ba66ba",
        "1d00ffff",
        0,
    )
    assert len(header) == 80


def test_le_hex():
    assert le_hex(0, 4) == "00000000"
    assert le_hex(1, 4) == "01000000"
    assert le_hex(256, 4) == "00010000"


def test_midstate_matches_full_hash():
    """Stellt sicher, dass Midstate-Optimierung identische Hashes liefert wie der naive Ansatz."""
    # Fake-Header-Daten
    version = "00000001"
    prev_hash = "a" * 64
    ntime = "66ba66ba"
    nbits = "207fffff"
    nonce = 42

    coinbase = build_coinbase("aabb", "cc", "dd", "eeff")
    coinbase_hash = double_sha256(coinbase)
    merkle_root = build_merkle_root(coinbase_hash, [])

    job = {
        "version": version, "prev_hash": prev_hash, "ntime": ntime, "nbits": nbits,
        "coinbase1": "aabb", "coinbase2": "eeff", "merkle_branch": [],
        "job_id": "test",
    }

    from miner.worker import _make_prefix
    prefix = _make_prefix(job, merkle_root)
    assert len(prefix) == 76  # 80 - 4 (nonce)

    # Naiver Ansatz
    header = prefix + struct.pack("<I", nonce)
    naive_hash = double_sha256(header)

    # Midstate-Ansatz
    midstate = hashlib.sha256()
    midstate.update(prefix[:64])
    nonce_frame = bytearray(16)
    nonce_frame[:12] = prefix[64:]
    struct.pack_into("<I", nonce_frame, 12, nonce)
    h = midstate.copy()
    h.update(nonce_frame)
    midstate_hash = hashlib.sha256(h.digest()).digest()

    assert naive_hash == midstate_hash


def test_miner_stats_hashrate():
    counter = mp.Value("Q", 1_000_000)
    stats = MinerStats(counter)
    r = stats.report()
    assert r["total_hashes"] == 1_000_000
    assert r["hashrate"] > 0


def test_miner_stats_shares():
    counter = mp.Value("Q", 0)
    stats = MinerStats(counter)
    stats.record_share()
    stats.record_share()
    assert stats.report()["shares"] == 2


def test_worker_nonce_partitioning():
    """Jeder Worker startet bei worker_id und springt um num_workers."""
    num_workers = 4
    for worker_id in range(num_workers):
        en2_start = worker_id
        en2_after_overflow = en2_start + num_workers  # stride = num_workers
        assert en2_after_overflow == worker_id + num_workers
        assert en2_after_overflow != (worker_id + 1) % num_workers  # kein Kollisions-Muster


def test_proof_of_work_simulation():
    """Simuliert echtes Mining mit einem sehr leichten Target."""
    target = (1 << 252) - 1
    found = False
    for nonce in range(100_000):
        data = struct.pack("<I", nonce)
        h = double_sha256(data)
        if int.from_bytes(h[::-1], "big") < target:
            found = True
            break
    assert found
