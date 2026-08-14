"""Tests für die Kern-Mining-Algorithmen."""
import hashlib
import struct

from miner.worker import (
    bits_to_target,
    build_coinbase,
    build_header,
    build_merkle_root,
    double_sha256,
    le_hex,
    MinerStats,
)


def test_double_sha256_known_value():
    # SHA256(SHA256("")) = 5df6e0e2...
    result = double_sha256(b"")
    assert result.hex() == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"


def test_bits_to_target_genesis():
    # Bitcoin Genesis-Block: nbits = 0x1d00ffff
    target = bits_to_target("1d00ffff")
    # Sollte 0x00000000FFFF0000...0000 sein
    expected = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    assert target == expected


def test_bits_to_target_easy():
    # Sehr leichtes Target: 0x207fffff (regtest standard)
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


def test_miner_stats_hashrate():
    stats = MinerStats()
    stats.add_hashes(1_000_000)
    r = stats.report()
    assert r["total_hashes"] == 1_000_000
    assert r["hashrate"] > 0


def test_miner_stats_shares():
    stats = MinerStats()
    stats.record_share()
    stats.record_share()
    assert stats.report()["shares"] == 2


def test_proof_of_work_simulation():
    """Simuliert echtes Mining mit einem sehr leichten Target."""
    target = (1 << 252) - 1  # Sehr einfaches Target
    nonce = 0
    found = False
    for nonce in range(100_000):
        data = struct.pack("<I", nonce)
        h = double_sha256(data)
        if int.from_bytes(h[::-1], "big") < target:
            found = True
            break
    assert found, "Sollte bei so leichtem Target sofort finden"
