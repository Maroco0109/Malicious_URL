from collections import defaultdict
from typing import Dict, Optional
from urllib.parse import urlparse

from publicsuffix2 import get_sld


def levenshtein_distance(a: str, b: str) -> int:
    """
    두 문자열 사이의 Levenshtein 거리를 계산합니다.
    시간 복잡도 O(N*M)인 표준 동적 계획법 구현입니다.
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
                prev_row[j] + 1,
                curr[j - 1] + 1,
                prev_row[j - 1] + cost,
            )
        prev_row = curr
    return prev_row[-1]


def _extract_registered_domain(hostname: str) -> Optional[str]:
    """
    Public suffix 정보를 활용해 최상위 등록 도메인을 추출합니다.
    mail.google.co.kr --> google.co.kr
    """
    if not hostname:
        return None
    sld = get_sld(hostname)
    if sld:
        return sld.lower()
    return hostname.lower()


def build_whitelist_index(whitelist: list[str]) -> Dict[int, list]:
    """
    화이트리스트를 도메인 길이 기준으로 버킷화해 후보군을 제한합니다.
    """
    buckets: Dict[int, list] = defaultdict(list)
    for entry in whitelist:
        normalized = entry.strip().lower()
        if not normalized:
            continue
        buckets[len(normalized)].append(normalized)
    return buckets


def _collect_candidate_domains(domain: str, index: Dict[int, list], max_distance: int) -> list[str]:
    candidates = []
    target_len = len(domain)
    min_len = max(1, target_len - max_distance)
    max_len = target_len + max_distance
    for length in range(min_len, max_len + 1):
        candidates.extend(index.get(length, []))
    return candidates


def check_typosquat(
    url_or_domain: str,
    whitelist: Optional[list[str]] = None,
    whitelist_index: Optional[Dict[int, list]] = None,
    max_distance: int = 2,
) -> dict:
    """
    입력 URL 또는 도메인에서 등록 도메인을 추출하고
    편집 거리 후보군만 평가해 타이포스쿼팅 여부를 판단합니다.
    """
    parsed = urlparse(url_or_domain)
    hostname = parsed.hostname or url_or_domain
    if not hostname:
        return {
            "domain": None,
            "suspected": False,
            "closest": None,
            "distance": None,
            "comment": "도메인 정보를 추출하지 못했습니다.",
        }

    domain = _extract_registered_domain(hostname)
    if not domain:
        domain = hostname.lower()

    if whitelist_index is None:
        if not whitelist:
            return {
                "domain": domain,
                "suspected": False,
                "closest": None,
                "distance": None,
                "comment": "화이트리스트를 제공해 주세요.",
            }
        whitelist_index = build_whitelist_index(whitelist)

    candidates = _collect_candidate_domains(domain, whitelist_index, max_distance)
    closest_domain = None
    closest_distance = max_distance + 1

    for candidate in candidates:
        dist = levenshtein_distance(domain, candidate)
        if dist < closest_distance:
            closest_distance = dist
            closest_domain = candidate
            if dist == 0:
                break

    if not closest_domain or closest_distance > max_distance:
        return {
            "domain": domain,
            "suspected": False,
            "closest": None,
            "distance": None,
            "comment": f"화이트리스트 도메인과 편집 거리 {max_distance} 이내에 해당하지 않습니다.",
        }

    if closest_distance == 0:
        return {
            "domain": domain,
            "suspected": False,
            "closest": closest_domain,
            "distance": closest_distance,
            "comment": "정상 도메인으로 판단되어 타이포스쿼팅이 아닙니다.",
        }

    return {
        "domain": domain,
        "suspected": True,
        "closest": closest_domain,
        "distance": closest_distance,
        "comment": f"가장 가까운 도메인: {closest_domain} (거리: {closest_distance})",
    }
