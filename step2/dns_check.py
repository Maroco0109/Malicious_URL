# step2/dns_check.py

import dns.resolver
import dns.exception


def query_dns_records(domain: str, record_types=None) -> dict:
    """
    주어진 도메인(예: google.com)에 대해, 요청한 레코드 타입 목록을 순차적으로 조회합니다.
    record_types 기본값은 ["A", "AAAA", "MX", "NS", "TXT", "CNAME"].
    TTL 정보도 함께 가져옵니다.
    """
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    results = {}
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            entries = []
            for rdata in answers:
                # 각 레코드마다 TTL을 뽑을 수 있도록 answers.response 섹션 검색
                ttl = answers.rrset.ttl if hasattr(answers, "rrset") else None
                # rdata.to_text() 로 문자열 형태로 레코드 값 추출
                entries.append({
                    "value": rdata.to_text(),
                    "ttl": ttl
                })
            results[rtype] = entries
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except dns.exception.DNSException as e:
            results[rtype] = {"error": str(e)}

    return results
