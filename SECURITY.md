# 보안 가이드라인

## ⚠️ 중요 보안 경고

이 도구는 잠재적으로 **악성 URL 및 웹사이트**를 분석하도록 설계되었습니다. 부적절한 사용은 시스템을 심각한 보안 위험에 노출시킬 수 있습니다.

### 핵심 경고사항

1. **프로덕션 시스템에서 절대 이 도구를 실행하지 마세요**
2. **항상 격리된 환경을 사용하세요** (Docker 컨테이너, VM, 샌드박스)
3. **신뢰할 수 있는 네트워크에서 URL을 분석하지 마세요** (적절한 격리 없이)
4. **악성 사이트가 브라우저 취약점을 악용할 수 있음을 인지하세요**

---

## 구현된 보안 기능

### 1. SSRF (Server-Side Request Forgery) 방어

모든 URL을 가져오기 전에 검증하여 다음을 방지합니다:
- 내부/사설 IP 주소 접근 (`127.0.0.1`, `192.168.x.x` 등)
- 클라우드 메타데이터 서비스 접근 (`169.254.169.254`)
- HTTP/HTTPS가 아닌 스킴 사용 (`file://`, `ftp://` 등)

**허용된 스킴:** `http`, `https`만 가능

**차단된 호스트:**
- `localhost`, `127.0.0.1`, `::1`
- `0.0.0.0`
- `169.254.169.254` (AWS 메타데이터)
- `metadata.google.internal` (GCP 메타데이터)
- 사설 IP 대역 (10.x.x.x, 172.16.x.x-172.31.x.x, 192.168.x.x)

### 2. 경로 순회(Path Traversal) 방어

모든 파일 작업이 검증되어 다음을 방지합니다:
- 허용된 디렉토리 외부의 파일 읽기
- 시스템 디렉토리에 쓰기
- 경로 순회 공격 (`../../../etc/passwd`)

**안전한 디렉토리:**
- 결과 저장: `url_examine/`

### 3. SSL/TLS 인증서 검증

기본적으로 SSL 인증서가 **검증**되어 중간자 공격(MITM)을 방지합니다.

- **기본값:** 인증서 검증 활성화
- **선택사항:** 유효하지 않은 인증서를 가진 사이트 분석을 위해 비활성화 가능
- **경고:** 검증 비활성화 시 MITM 공격에 취약해집니다

### 4. 요청 제한(Rate Limiting)

HTTP 요청이 제한되어 다음을 방지합니다:
- 우발적 DDoS 공격
- API 할당량 소진
- 대상 시스템의 탐지

**기본 제한:**
- 정적 HTML 분석: 60초당 30회 요청

### 5. 콘텐츠 검증

- **Content-Type 확인:** HTML/텍스트 응답만 처리
- **크기 제한:** 최대 10MB 응답 크기
- **타임아웃 제한:** 1-30초 (제한됨)

### 6. 브라우저 샌드박스

Selenium을 사용한 동적 분석:
- **기본값:** 샌드박스 활성화 (권장)
- **선택사항:** 호환성을 위해 비활성화 가능 (⚠️ 위험)
- 추가 보안: 확장 프로그램, 플러그인, 위치정보 비활성화

### 7. 오류 메시지 정제

정보 노출을 방지하기 위해 오류 메시지가 정제됩니다:
- 내부 경로가 노출되지 않음
- 라이브러리 버전이 숨겨짐
- 상세한 오류는 디버그 모드에서만 표시

### 8. API 키 검증

OpenAI API 키가 다음 사항에 대해 검증됩니다:
- 올바른 형식 (`sk-` 접두사)
- 최소 길이
- 비어있지 않은 값

---

## 권장 사용법

### 1. Docker 격리 (권장)

```dockerfile
# Dockerfile 예제
FROM python:3.11-slim

# 의존성 설치
RUN apt-get update && apt-get install -y \\
    chromium-browser \\
    chromium-chromedriver \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 비-루트 사용자로 실행
RUN useradd -m -u 1000 analyzer
USER analyzer

CMD ["python", "main.py"]
```

**네트워크 격리와 함께 실행:**
```bash
docker run --rm \\
    --network none \\
    -v $(pwd)/url_examine:/app/url_examine \\
    malicious-url-detector \\
    python main.py --url "https://suspicious.com" --export-json results.json
```

### 2. 가상 머신 (Virtual Machine)

- 일회용 VM 사용 (AWS EC2, Azure VM, GCP Compute)
- 분석 전 스냅샷 생성
- 격리된 네트워크 세그먼트 사용
- 각 분석 후 스냅샷에서 복원

### 3. 보안 샌드박스 (Firejail, Bubblewrap)

```bash
# Firejail 사용
firejail --net=none --private=tmp \\
    python main.py --url "https://suspicious.com"
```

---

## 설정 옵션

### 보안 기능 비활성화 (⚠️ 주의해서 사용)

```python
# 사설 IP 분석 허용 (내부 모의침투 테스트용)
from step3.static_check import check_static_threat
result = check_static_threat(url, allow_private_ips=True)

# 브라우저 샌드박스 비활성화 (호환성)
from step3.dynamic_check import check_dynamic_threat
result = check_dynamic_threat(url, disable_sandbox=True)  # ⚠️ 위험

# SSL 검증 비활성화 (유효하지 않은 인증서)
from step1.ssl_check import get_certificate_info
result = get_certificate_info(url, verify_cert=False)  # ⚠️ MITM 취약
```

**보안 기능을 비활성화해야 하는 경우:**
- 내부 네트워크 테스트 (allow_private_ips)
- 자체 서명된 인증서를 가진 사이트 분석 (verify_cert=False)
- 컨테이너 환경에서의 호환성 문제 (disable_sandbox)

**다음의 경우 보안 기능을 절대 비활성화하지 마세요:**
- 알려지지 않은/신뢰할 수 없는 URL 분석
- 공유 인프라에서 실행
- 프로덕션 네트워크에 연결된 상태

---

## 보안 체크리스트

분석 실행 전:

- [ ] 격리된 환경에서 실행 중 (VM/Docker)
- [ ] 네트워크가 격리되었거나 모니터링 중
- [ ] 일회용/복원 가능한 시스템 사용
- [ ] 분석 머신에 민감한 데이터 없음
- [ ] 방화벽 규칙 구성됨
- [ ] 모니터링/로깅 활성화됨
- [ ] API 키가 하드코딩되지 않음
- [ ] `.env` 파일이 `.gitignore`에 포함됨

---

## 사고 대응

분석 중 시스템 손상이 의심되는 경우:

1. **즉시 시스템 격리**
   - 네트워크 연결 해제
   - VM/컨테이너 중단

2. **사고 문서화**
   - 분석한 URL
   - 시간
   - 관찰된 행동
   - 오류 메시지

3. **깨끗한 상태로 복원**
   - VM 스냅샷 복원
   - Docker 컨테이너 재구축
   - 필요시 완전 초기화 및 재설치

4. **로그 검토**
   - 네트워크 연결 확인
   - 파일 시스템 변경사항 검토
   - 브라우저 로그 분석

---

## 보안 업데이트

보안 취약점은 다음으로 보고할 수 있습니다:
- GitHub Issues (중요하지 않은 이슈)
- 보안 이메일: [보안 담당자 연락처]

### 의존성 보안 유지

```bash
# 의존성 감사
pip install safety
safety check

# 의존성 업데이트
pip install --upgrade -r requirements.txt

# 알려진 취약점 확인
pip install pip-audit
pip-audit
```

---

## 추가 리소스

- [OWASP 웹 보안 테스팅 가이드](https://owasp.org/www-project-web-security-testing-guide/)
- [SANS Internet Storm Center](https://isc.sans.edu/)
- [VirusTotal](https://www.virustotal.com/)
- [URLhaus](https://urlhaus.abuse.ch/)

---

## 면책조항

이 도구는 **합법적인 보안 연구 및 방어 목적으로만** 제공됩니다. 사용자는 다음 사항에 책임이 있습니다:

- 웹사이트 분석 전 적절한 승인 획득
- 관련 법률 및 규정 준수
- 악성코드 분석의 위험 이해 및 수용
- 적절한 안전 조치 사용

**이 도구의 오용이나 손상에 대해 저자는 책임지지 않습니다.**

---

*최종 업데이트: 2025*
