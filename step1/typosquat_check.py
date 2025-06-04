import difflib
from urllib.parse import urlparse


def levenshtein_distance(a: str, b: str) -> int:
    """
    순수 파이썬으로 두 문자열의 Levenshtein 거리 계산
    (시간 복잡도가 O(N*M)임에 유의)
    """
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                prev_row[j] + 1,       # 삭제
                curr[j - 1] + 1,       # 삽입
                prev_row[j - 1] + cost # 교체
            )
        prev_row = curr
    return prev_row[-1]


def extract_domain_without_www(hostname: str) -> str:
    """
    www. 접두사가 있으면 제거하고,
    서브도메인을 제외하고 최상위 도메인+TLD만 리턴.
    ex) mail.google.com → google.com
    """
    # www. 제거
    if hostname.startswith("www."):
        hostname = hostname[4:]
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    # 예: mail.google.co.kr → 뒤에서 두 개만 사용하여 co.kr
    return ".".join(parts[-2:])


def check_typosquat(url_or_domain: str, whitelist: list, max_distance: int = 2) -> dict:
    """
    URL 또는 도메인 문자열을 입력받아, 화이트리스트(정상 도메인 리스트)와 편집거리를 계산합니다.
    만약 “편집거리 == 0” (정확히 자기 자신과 일치) 이면 suspected=False로 처리하고,
    그 외에 “편집거리 ≤ max_distance”면 suspected=True로 리턴합니다.
    """
    # 1) urlparse 로 파싱해서 hostname 시도
    parsed = urlparse(url_or_domain)
    hostname = parsed.hostname

    # 2) parsed.hostname이 None이면, 인자로 넘어온 문자열 자체가 도메인일 수 있음
    if not hostname:
        hostname = url_or_domain

    domain = extract_domain_without_www(hostname.lower())
    results = []

    for legit in whitelist:
        dist = levenshtein_distance(domain, legit.lower())
        if dist <= max_distance:
            results.append((legit, dist))

    # 편집거리가 작은 순으로 정렬
    results.sort(key=lambda x: x[1])

    # 화이트리스트 내에 편집거리 ≤ max_distance인 대상이 없음
    if len(results) == 0:
        return {
            "domain": domain,
            "suspected": False,
            "closest": None,
            "distance": None,
            "comment": f"화이트리스트 도메인과 편집거리 ≤ {max_distance}인 대상이 없습니다."
        }

    closest_domain, closest_dist = results[0]

    # 편집거리 0인 경우 → 자기 자신과 일치, 오탐 방지를 위해 suspected=False
    if closest_dist == 0:
        return {
            "domain": domain,
            "suspected": False,
            "closest": closest_domain,
            "distance": closest_dist,
            "comment": "편집거리가 0이므로 화이트리스트에 정확히 일치하는 정상 도메인입니다."
        }

    # 그 외(거리 1 또는 2)인 경우에는 suspected=True
    return {
        "domain": domain,
        "suspected": True,
        "closest": closest_domain,
        "distance": closest_dist,
        "comment": f"가장 근접한 도메인: {closest_domain} (거리: {closest_dist})"
    }
