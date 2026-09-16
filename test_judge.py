import time

from judge import judge

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_eicar_is_malicious():
    assert judge(EICAR) == "malicious"


def test_eicar_variant_not_in_hash_blacklist_is_still_malicious():
    variant = b"---prefix---" + EICAR + b"---suffix---"
    assert judge(variant) == "malicious"


def test_plain_text_is_safe():
    assert judge(b"just a normal file") == "safe"


def test_empty_bytes_is_safe():
    assert judge(b"") == "safe"


def test_non_eicar_binary_is_safe():
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    assert judge(png_header) == "safe"


def test_judge_completes_within_reasonable_time():
    for sample in (EICAR, b"just a normal file"):
        start = time.perf_counter()
        judge(sample)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 100
