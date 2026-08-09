import base64

from voidrecon.utils.hashing import favicon_hash, murmur3_x86_32, sha256_hex

# Reference values produced by the mmh3 package (kept as constants so the test
# has no third-party dependency).
_VECTORS = {
    b"": 0,
    b"hello": 613153351,
    b"foo": -156908512,
    b"The quick brown fox": 1621279277,
}


def test_murmur3_matches_reference_vectors():
    for data, expected in _VECTORS.items():
        assert murmur3_x86_32(data) == expected


def test_murmur3_signed_range():
    for data in (b"a", b"abcd", b"abcde", b"x" * 100):
        h = murmur3_x86_32(data)
        assert -(2**31) <= h < 2**31


def test_favicon_hash_uses_base64_with_newlines():
    content = b"\x00\x00\x01\x00" + b"ABCD" * 40
    assert favicon_hash(content) == murmur3_x86_32(base64.encodebytes(content))


def test_sha256_hex():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
