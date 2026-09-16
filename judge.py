import hashlib
import time

import yara

HASH_BLACKLIST = {
    "13db60afb914a2ee9b3649d1947d58046d1a9e9b8e4114d80b1d5c142b4ed7fa", #EICAR
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
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    safe = b"just a normal file"

    for name, sample in [("eicar", eicar), ("safe", safe)]:
        start = time.perf_counter()
        result = judge(sample)
        elapsed = (time.perf_counter() - start) * 1000
        print(f"{name}: {result} ({elapsed:.3f}ms)")