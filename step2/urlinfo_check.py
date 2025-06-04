# step2/urlinfo_check.py

from urllib.parse import urlparse, parse_qs
import os


def parse_url_info(url: str) -> dict:
    """
    URL 구조를 분석하여 스킴, 호스트, 포트(명시적이거나 기본값), 경로(path), 쿼리 파라미터, 파일명/확장자 등을 반환합니다.
    또한 쿼리에 redirect, url, download 같은 “리디렉션 의심 키워드”가 있는지 간단히 검사합니다.
    """

    parsed = urlparse(url)
    scheme = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port or (443 if scheme.lower() == "https" else 80 if scheme.lower() == "http" else None)
    path = parsed.path or "/"
    query = parsed.query

    # 파일명 및 확장자 (예: /download/malware.exe → filename=malware.exe, ext=.exe)
    filename = os.path.basename(path) if os.path.basename(path) else ""
    ext = os.path.splitext(filename)[1] if filename else ""

    # 쿼리 파라미터 dict로 변환
    query_params = parse_qs(query)

    # 의심 키워드가 있는지(redirect, url, download 등)
    suspicious_keys = []
    for key in query_params.keys():
        low = key.lower()
        if any(tok in low for tok in ["redirect", "url", "download", "file", "continue"]):
            suspicious_keys.append(key)

    return {
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": path,
        "filename": filename,
        "extension": ext,
        "query_string": query,
        "query_params": query_params,
        "suspicious_query_keys": suspicious_keys,
        "comment": "URL 구조 및 쿼리 리디렉션 가능성 키워드 반환"
    }
