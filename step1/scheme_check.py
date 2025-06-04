# step1/scheme_check.py

from urllib.parse import urlparse

def check_scheme_and_port(url: str) -> dict:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname

    # 명시적 포트가 없으면 scheme에 따라 기본값을 할당
    if parsed.port:
        port = parsed.port
    else:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443
        else:
            port = None

    issues = []
    # 1) 스킴 검사
    if scheme not in ("http", "https"):
        issues.append(f"비표준 스킴 사용: {scheme}")

    # 2) 포트 검사 (명시적이든 기본값이든)
    if port:
        if scheme == "http" and port != 80:
            issues.append(f"HTTP인데 포트가 {port}로 설정됨 (표준:80)")
        if scheme == "https" and port != 443:
            issues.append(f"HTTPS인데 포트가 {port}로 설정됨 (표준:443)")

    return {
        "hostname": hostname,
        "scheme": scheme,
        "port": port,
        "issues": issues or ["문제 없음"],
        "comment": "스킴/포트 관련 잠재적 의심 요소 반환"
    }
