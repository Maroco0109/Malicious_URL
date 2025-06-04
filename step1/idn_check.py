# step1/idn_check.py

import idna
import unicodedata
from urllib.parse import urlparse


def normalize_domain(domain: str) -> str:
    """
    주어진 도메인을 NFC 정규화 후 Punycode로 변환했다가 다시 디코딩해서 반환.
    IDN이 섞인 도메인인지 확인하기 위한 용도로 사용.
    """
    # 유니코드 정규화
    norm = unicodedata.normalize("NFC", domain)
    try:
        # Punycode 인코딩/디코딩
        puny = idna.encode(norm).decode("ascii")
        decoded = idna.decode(puny)
    except idna.IDNAError:
        # 인코딩/디코딩 실패 시, 애초에 비정상 도메인으로 간주
        return None
    return decoded


def check_idn(url: str) -> dict:
    """
    URL에서 도메인(호스트부분)을 추출하여, 
    1) Punycode 형식을 사용하는지 여부
    2) 정규화된 도메인과 원래 도메인이 달라지는지 여부
    결과를 dict 형태로 반환.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return {"error": "유효한 호스트를 URL에서 추출할 수 없습니다."}

    try:
        # Punycode로 인코딩되어 있는지?
        puny = idna.encode(hostname).decode("ascii")
        # 디코딩해서 원래 문자열과 비교
        decoded = idna.decode(puny)
    except idna.IDNAError:
        # IDNA 인코딩/디코딩 실패 → 비정상 IDN 의심
        return {
            "hostname": hostname,
            "is_idn": False,
            "normalized": None,
            "comment": "IDNA 인코딩/디코딩 도중 오류 발생"
        }

    is_using_puny = hostname.startswith("xn--") or ("xn--" in hostname)
    normalized = decoded  # Punycode 디코딩 결과

    return {
        "hostname": hostname,
        "is_idn": is_using_puny,
        "normalized": normalized,
        "comment": "원래 호스트와 정규화 결과 비교 필요"
    }
