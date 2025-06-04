import whois
import datetime


def get_whois_info(domain: str) -> dict:
    """
    주어진 도메인(예: google.com)에 대해 WHOIS 조회를 수행합니다.
    도메인 생성일, 갱신일, 만료일, 등록자, 등록 기관 등을 반환합니다.
    """

    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"error": f"WHOIS 조회 실패: {e}"}

    # whois.whois() 결과는 dict 형태로 반환되며,
    # 생성일(create_date), 만료일(expiration_date), 갱신일(updated_date) 등이 리스트 또는 단일값으로 들어옵니다.
    # 일관된 형태로 출력하기 위해 다음과 같이 처리합니다.

    def _normalize_date(val):
        if isinstance(val, list):
            # 리스트 중 가장 최근(또는 첫 번째)을 골라서 isoformat
            for v in val:
                if isinstance(v, datetime.datetime):
                    return v.isoformat()
            return None
        elif isinstance(val, datetime.datetime):
            return val.isoformat()
        else:
            return None

    created = _normalize_date(w.creation_date)
    updated = _normalize_date(w.updated_date)
    expires = _normalize_date(w.expiration_date)

    return {
        "domain_name": w.domain_name if w.domain_name else domain,
        "registrar": w.registrar or "",
        "whois_server": w.whois_server or "",
        "creation_date": created,
        "updated_date": updated,
        "expiration_date": expires,
        "name_servers": w.name_servers or [],
        "emails": w.emails or [],
        "status": w.status or "",
    }
