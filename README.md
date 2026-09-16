# poc3-yara-detection

PoC 3 — 서버 판정(해시 대조 + YARA 매칭) 검증: EICAR 테스트 파일로 실제 악성/안전 판정이 나오는지 확인.

관련 이슈: [2026-Teecher-Team-C/poc3-yara-detection#1](https://github.com/2026-Teecher-Team-C/poc3-yara-detection/issues/1)

## 검증 목표

서버가 YARA 룰과 SHA256 해시 대조를 통해 악성/안전 파일을 실제로 판정할 수 있는지 확인한다.

## 구성

- `eicar.yar` — EICAR 표준 테스트 문자열을 탐지하는 최소 YARA 룰
- `judge.py` — 해시 블랙리스트 대조 → YARA 매칭 순으로 판정하는 `judge(data: bytes) -> str` 함수와, 판정 소요 시간을 재는 실행 스크립트
- `requirements.txt` — 의존성 (`yara-python`)

## 실행 방법

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python judge.py
```

## 판정 로직

1. 입력 데이터의 SHA256 해시를 계산해 블랙리스트(`HASH_BLACKLIST`)에 있는지 대조
2. 블랙리스트에 없으면 YARA 룰(`eicar.yar`)로 패턴 매칭
3. 둘 중 하나라도 걸리면 `"malicious"`, 아니면 `"safe"` 반환

## 해시 블랙리스트

`judge.py`의 `HASH_BLACKLIST`에는 현재 EICAR 표준 테스트 문자열의 SHA256 해시 1개만 들어있다.

```
13db60afb914a2ee9b3649d1947d58046d1a9e9b8e4114d80b1d5c142b4ed7fa
```

계산 방법 — EICAR 바이트를 `hashlib.sha256()`으로 해싱:

```powershell
python -c "import hashlib; data = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'; print(hashlib.sha256(data).hexdigest())"
```

PoC 단계라 블랙리스트를 코드에 하드코딩된 `set`으로 두었다. 실제 서비스에서는 알려진 악성코드 해시 DB(예: 외부 위협 인텔리전스 피드, 자체 수집 이력)와 연동해 채워야 하며, 이 부분은 본 PoC 범위 밖이다.

## 검증 결과

| 입력 | 판정 | 소요 시간 |
| --- | --- | --- |
| EICAR 테스트 문자열 | `malicious` | 0.255ms |
| 일반 텍스트 | `safe` | 0.121ms |

이슈에 명시된 성공 기준(EICAR → 악성 판정, 일반 파일 → 안전 판정, 판정 소요 시간 측정) 3가지를 모두 충족했다.

## 자동화 테스트

위 표는 수동 실행(`python judge.py`) 결과다. 이를 반복 가능한 형태로 고정하기 위해 `test_judge.py`에 pytest 테스트를 추가했다.

```powershell
pip install -r requirements.txt
pytest -v
```

기존 수동 테스트로는 EICAR 표준 문자열이 해시 블랙리스트와 YARA 룰 양쪽에 모두 걸리기 때문에, 실제로 둘 중 어느 판정 경로가 동작했는지 구분할 수 없었다. `test_eicar_variant_not_in_hash_blacklist_is_still_malicious`는 EICAR 문자열 앞뒤에 패딩을 붙여 해시는 블랙리스트에 없지만 YARA 패턴은 여전히 매칭되는 변종을 사용해, **해시 대조 없이 YARA 매칭만으로도 탐지된다**는 것을 별도로 검증한다. 그 외 빈 바이트열·PNG 헤더 등 일반 텍스트가 아닌 입력에 대한 오탐 여부, 판정 소요 시간(100ms 이내) 어서션도 포함했다.

## 참고: 왜 파일이 아니라 바이트로 테스트했나

EICAR 표준 문자열을 그대로 디스크에 파일로 저장하면 Windows Defender 등 백신이 즉시 탐지해 파일을 격리/삭제한다. 이는 실제로 겪은 문제이며, 본 플랫폼이 스풀 파일을 XOR 인코딩해서 저장하기로 한 보안 설계와도 맞닿아 있다. 그래서 이 PoC에서는 `yara.compile(...).match(data=...)`로 파일을 거치지 않고 바이트를 직접 스캔하는 방식으로 검증했다.

