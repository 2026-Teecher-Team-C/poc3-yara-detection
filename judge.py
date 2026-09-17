import hashlib
import time

import yara

HASH_BLACKLIST = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", #EICAR
}

_rule = yara.compile(filepath = "eicar.yar")

def judge(data : bytes) -> str:
    sha256 = hashlib.sha256(data).hexdigest()

    if sha256 in HASH_BLACKLIST:
        return "malicious"

    if _rule.match(data=data):
        return "malicious"

    return "safe"


if __name__ == "__main__":
    import os

    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_variant = b"---prefix---" + eicar + b"---suffix---"
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + os.urandom(200)
    pdf_header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj" + os.urandom(200)
    zip_header = b"PK\x03\x04" + os.urandom(200)

    samples = [
        ("eicar (표준 테스트 문자열)", eicar),
        ("eicar_variant (해시 불일치, YARA만 매칭)", eicar_variant),
        ("plain_text", b"just a normal file"),
        ("empty_bytes", b""),
        ("png_like (1KB)", png_header),
        ("pdf_like (1KB)", pdf_header),
        ("zip_like (1KB)", zip_header),
        ("large_safe_file (1MB)", os.urandom(1024 * 1024)),
    ]

    for name, sample in samples:
        start = time.perf_counter()
        result = judge(sample)
        elapsed = (time.perf_counter() - start) * 1000
        print(f"{name}: {result} ({elapsed:.3f}ms)")