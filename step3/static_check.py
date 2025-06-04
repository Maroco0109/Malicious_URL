# step3/static_check.py

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse


def fetch_html(url: str, timeout: float = 10.0) -> str:
    """
    requests를 이용해 주어진 URL의 HTML을 가져옴.
    실패 시 빈 문자열("") 반환.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        # 텍스트 인코딩이 설정되어 있지 않으면 resp.apparent_encoding 사용
        if resp.encoding is None:
            resp.encoding = resp.apparent_encoding
        return resp.text
    except Exception as e:
        return ""


def check_static_threat(url: str) -> dict:
    """
    1) HTML을 가져와서
    2) <script> 태그 내 위험 키워드 탐지 (eval, document.write, innerHTML, atob 등)
    3) meta refresh 태그 탐지
    4) 외부 스크립트(src 속성)에서 악성 의심 도메인 패턴 탐지 (예: IP 직통 호출, 비표준 포트 포함 URL)
    5) iframe 태그 탐지 (숨겨진 iframe)
    6) 의심 URL 파라미터(ex: redirect=, url=, download= 등) 검출
    결과를 dict로 반환.
    """

    result = {
        "url": url,
        "html_fetched": False,
        "suspicious_scripts": [],
        "num_eval": 0,
        "num_document_write": 0,
        "num_innerhtml": 0,
        "num_atob": 0,
        "num_meta_refresh": 0,
        "meta_refresh_contents": [],
        "external_scripts": [],
        "num_iframe": 0,
        "iframe_srcs": [],
        "suspicious_query_keys": [],
        "comment": ""
    }

    html = fetch_html(url)
    if not html:
        result["comment"] = "HTML을 가져오지 못함(요청 실패 또는 빈 응답)"
        return result

    result["html_fetched"] = True
    soup = BeautifulSoup(html, "lxml")

    # 1) <script> 태그 내 위험 키워드 탐지
    script_tags = soup.find_all("script")
    for tag in script_tags:
        src = tag.get("src")
        if src:
            # 외부 스크립트 URL 수집
            result["external_scripts"].append(src)
        code = tag.string or ""
        # eval( 패턴
        eval_count = len(re.findall(r"\beval\s*\(", code))
        if eval_count > 0:
            result["num_eval"] += eval_count
            result["suspicious_scripts"].append({"type": "eval", "count": eval_count, "snippet": code[:100]})
        # document.write
        dw_count = len(re.findall(r"\bdocument\.write\s*\(", code))
        if dw_count > 0:
            result["num_document_write"] += dw_count
            result["suspicious_scripts"].append({"type": "document.write", "count": dw_count, "snippet": code[:100]})
        # innerHTML
        ih_count = len(re.findall(r"\.innerHTML", code))
        if ih_count > 0:
            result["num_innerhtml"] += ih_count
            result["suspicious_scripts"].append({"type": "innerHTML", "count": ih_count, "snippet": code[:100]})
        # atob (Base64 디코딩 함수)
        b64_count = len(re.findall(r"\batob\s*\(", code))
        if b64_count > 0:
            result["num_atob"] += b64_count
            result["suspicious_scripts"].append({"type": "atob", "count": b64_count, "snippet": code[:100]})

    # 2) <meta http-equiv="refresh"> 태그 탐지
    meta_tags = soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
    for m in meta_tags:
        result["num_meta_refresh"] += 1
        content = m.get("content", "")
        result["meta_refresh_contents"].append(content)

    # 3) <iframe> 태그 탐지
    iframe_tags = soup.find_all("iframe")
    for iframe in iframe_tags:
        result["num_iframe"] += 1
        src = iframe.get("src", "")
        result["iframe_srcs"].append(src)

    # 4) URL 파라미터(redirect, url, download 등) 체크
    parsed = urlparse(url)
    query = parsed.query
    # 쿼리 키 추출
    from urllib.parse import parse_qs
    params = parse_qs(query)
    for key in params.keys():
        low = key.lower()
        if any(tok in low for tok in ["redirect", "url", "download", "file", "continue"]):
            result["suspicious_query_keys"].append(key)

    # 5) comment 작성
    comments = []
    if result["num_eval"] > 0:
        comments.append(f"eval() 사용 횟수: {result['num_eval']}")
    if result["num_document_write"] > 0:
        comments.append(f"document.write() 사용 횟수: {result['num_document_write']}")
    if result["num_innerhtml"] > 0:
        comments.append(f"innerHTML 사용 횟수: {result['num_innerhtml']}")
    if result["num_atob"] > 0:
        comments.append(f"Base64 디코딩(atob) 사용 횟수: {result['num_atob']}")
    if result["num_meta_refresh"] > 0:
        comments.append(f"meta refresh 태그 발견: {result['num_meta_refresh']}개")
    if result["num_iframe"] > 0:
        comments.append(f"iframe 태그 발견: {result['num_iframe']}개")
    if result["suspicious_query_keys"]:
        comments.append(f"의심 쿼리 파라미터 키: {', '.join(result['suspicious_query_keys'])}")

    if not comments:
        result["comment"] = "정적 분석 단계에서 특별한 위험 토큰이 발견되지 않음"
    else:
        result["comment"] = "; ".join(comments)

    return result
