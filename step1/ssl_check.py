# step1/ssl_check.py

import ssl
import socket
import datetime
from urllib.parse import urlparse

# cryptography 쪽 모듈 import
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def get_certificate_info(url: str, timeout: float = 3.0, verify_cert: bool = True) -> dict:
    """
    HTTPS URL에 대해 SSL 핸드셰이크로부터 인증서를 가져온 뒤,
    cryptography 라이브러리로 파싱하여 issuer, subject, 유효기간, SAN 등을 반환합니다.
    (getpeercert(binary_form=True) 방식)
    """

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    if parsed.scheme.lower() != "https":
        return {"error": "HTTPS 스킴이 아닌 URL에서는 SSL 정보를 가져올 수 없습니다."}

    # SSL 컨텍스트 생성
    ctx = ssl.create_default_context()

    if not verify_cert:
        # ⚠️ WARNING: 인증서 검증을 비활성화하면 MITM 공격에 취약해집니다
        # 악성 사이트 분석 목적으로만 사용하고, 신뢰할 수 없는 네트워크에서는 사용하지 마세요
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        # 프로덕션 환경에서는 인증서 검증 활성화 권장
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        # 소켓 연결 후, binary_form=True로 인증서(DER) 가져오기
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
    except Exception as e:
        return {"error": f"SSL 연결/인증서 가져오기 실패: {e}"}

    if not der_cert:
        return {"error": "getpeercert(binary_form=True) 반환값이 없습니다."}

    # cryptography 를 통해 DER 인증서를 파싱
    try:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
    except Exception as e:
        return {"error": f"cryptography로 인증서 파싱 실패: {e}"}

    # issuer 추출
    issuer = cert.issuer.rfc4514_string()  # 예: "C=US,O=Google Trust Services,CN=WR2"
    # subject 추출
    subject = cert.subject.rfc4514_string()  # 예: "CN=*.google.com"
    # 유효기간 추출 (UTC 기준 사용 - 권장)
    not_before = cert.not_valid_before_utc.isoformat()
    not_after = cert.not_valid_after_utc.isoformat()

    # SAN(DNS) 추출
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_list = []

    # 도메인 일치 여부
    domain_match = False
    if hostname:
        # subject의 CN에 와일드카드(*)가 있을 수 있으므로, 단순 비교보다는 SAN 리스트 포함 여부로 체크
        if hostname in san_list:
            domain_match = True
        else:
            # 와일드카드 매칭도 간단 확인
            for name in san_list:
                if name.startswith("*.") and hostname.endswith(name[1:]):
                    domain_match = True
                    break

    # 파싱 결과 반환
    comment = "cryptography를 활용해 issuer, subject, 유효기간, SAN, 도메인 일치 여부를 반환"
    if not verify_cert:
        comment += " [⚠️ 경고: 인증서 검증 비활성화됨 - MITM 공격 가능]"

    return {
        "hostname": hostname,
        "issuer": issuer,
        "subject": subject,
        "not_before": not_before,
        "not_after": not_after,
        "domain_match": domain_match,
        "san_list": san_list,
        "cert_verified": verify_cert,
        "comment": comment
    }
