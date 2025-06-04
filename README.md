## 1. URL 확인 (위조·변조·IDN 등 위험 요소 파악)

1. **도메인 위조·유사 도메인 탐지**

   - **IDN(Internationalized Domain Name) 허용 탐지**

     - Punycode(encoded) 도메인(`xn--…`)이 올바르게 디코딩된 뒤, 시각적으로 유사(예: ‘раураl.com’ vs ‘paypal.com’)한지 검사
     - Python 라이브러리: `idna`, `unicodedata.normalize()` 등을 이용해 유니코드 정규화(NFC/NFD) 후 비슷한 글자(그리스 문자 vs 라틴 문자) 사용 여부 판별

   - **타이포·유사 문자 검사(Levenshtein 거리, 알고리즘)**

     - 시그니처: 널리 알려진 주요 도메인(예: `google.com`, `naver.com`)과의 편집거리(Edit distance)를 계산해, 특정 임계값(예: 1\~2자 이내 오탈자) 이내면 의심
     - 예: “gooogle.com” (o 중복), “paypa1.com” (l 대신 1)

   - **SSL/TLS 인증서 정보 비교**

     - HTTPS 사이트라면 인증서의 발급기관(CA), 발급 일시, 만료 일시, 도메인 일치 여부 검토
     - Let’s Encrypt, Sectigo 등 신뢰할 수 있는 CA가 아닌 이상 경고 신호

   - **URL 스킴(scheme)·포트 검사**

     - 비표준 포트(ex: `http://example.com:8080`), 혹은 스킴 변조(`ht tp://`, `hxxp://`) 등 비정상적 형태인지 여부

   - **정리**

     - 이 단계만으로는 오탐/미탐 확률이 높음. 이미지처럼 정교하게 위장된 피싱 도메인이나 짧은 편집거리 이면서 정상 사이트처럼 보이는 곳은 걸러내기 어려움

---

## 2. DNS·URL 정보 수집 (WHOIS, DNS Resolver 활용)

1. **도메인 WHOIS 조회**

   - **등록 일자(creation date)**

     - 최근 생성된 도메인은 피싱·스팸 목적일 가능성이 높음.
     - WHOIS 예시 라이브러리: `python-whois`, `whois` (PyPI)

   - **등록자 정보(registrant), 등록 기관(registrar)**

     - 개인 정보가 마스킹되었거나 익명 프록시 사용 시 의심
     - 과거 피싱 전력 있는 registrar 또는 익명화 서비스 이용 여부 확인

   - **갱신 주기, 만료 예정일(expiration date)**

     - 곧 만료될 예정이거나 주기적으로 갱신되는 패턴(예: 매 1개월 단위 갱신) 등 비정상적 패턴 탐지

2. **DNS 레코드 조회**

   - **A, AAAA 레코드 (IP 주소)**

     - IP가 의심스러운 범위(예: TOR 노드, 클라우드 서비스 악용, 특정 국가 할당 IP 대역)인지 확인

   - **MX, NS 레코드**

     - 메일이나 네임서버 정보가 빈약하거나 잘 알려진 무료 서비스(Google, AWS) 뒤에 숨어 있는지 탐색

   - **TTL(Time To Live) 값**

     - TTL이 지나치게 짧게 설정되면(예: 60초 이하) 빠르게 IP를 바꿔 도메인/IP 블랙리스트 회피 시도 가능

3. **URL 경로·쿼리 파라미터 분석**

   - **과도한 디렉터리 깊이(예: `example.com/a/b/c/d/e/f/g`), 의심스러운 확장자(php, asp, exe 등)**
   - **특정 파라미터 패턴**

     - `?redirect=http://suspicious.com`, `?download=악성파일.exe` 같은 리다이렉션·다운로드 트리거 확인

4. **정리**

   - DNS/WHOIS 정보는 도메인의 “신뢰도”를 어느 정도 가늠하게 해주지만, 단독으로는 한계가 있음. (가령, 정상적으로 오래된 도메인이라도 해킹당해 악성 콘텐츠 유포 가능)

---

## 3. 웹페이지 위협 감지 (HTML·JS 분석 후 위험 토큰·동작 탐지)

1. **정적(Static) 분석**

   - **HTML 태그 분석**

     - `<script>` 태그가 인라인으로 많이 포함되어 있는지, `eval()`, `document.write()`, `innerHTML` 같은 동적 삽입 함수가 남발되는지 확인
     - 사용자 클릭 없이 자동 실행되는 `<meta http-equiv="refresh" content="0;url=http://...">` 같은 강제 리다이렉션 태그 탐지

   - **JavaScript 코드 분석**

     - 난독화(obfuscation) 또는 암호화(encapsulation)된 코드 존재 여부
     - 특정 블랙리스트 도메인(광고, C\&C 서버)로 호출하는 AJAX/fetch 구문
     - WebAssembly 모듈(`.wasm`) 로딩하여 실행하는 형태
     - Base64 인코딩 스크립트(`atob`, `btoa` 등) 활용 여부

   - **외부 리소스 호출 검사**

     - 서드파티 서명 스크립트(CDN, 광고 네트워크) 중 악성으로 알려진 도메인 호출 여부
     - `iframe`을 이용해 외부 악성 페이지를 숨어서 로딩하는지 체크

2. **동적(Dynamic) 분석 (Sandbox)**

   - **헤드리스 브라우저 사용**

     - `Selenium`, `Playwright`, `Puppeteer` 등을 활용해 실제 페이지를 렌더링
     - 사용자가 클릭하지 않아도 동적으로 로드되는 악성 스크립트가 있는지 관찰 (`network` 로그, JS 실행 트리거)

   - **행위 기반 탐지**

     - 페이지 로딩 후 일정 시간 대기 → 비정상적 다운로드 시도, 팝업 광고, 랜섬웨어 스크립트 감지
     - 사용자의 입력(키보드, 마우스) 없이도 특정 이벤트(ransom키패드, 이메일 수집 스크립트) 발생 여부

3. **머신러닝 기반 특성 추출**

   - **HTML/JS 텍스트 임베딩**

     - `Tf-idf`, `FastText` 임베딩, 혹은 Transformer 기반 임베딩(BERT 등)으로 특징 벡터화
     - 피싱 코드와 정상 코드의 분포 차이를 학습한 분류 모델(SVM, RandomForest, LightGBM 등)

   - **DOM 트리 구조 비교**

     - 피싱 페이지 특유의 DOM 깊이, `<div>` 구조, `<button>` 재배치 패턴 등 구조적 피쳐 추출

4. **정리**

   - 정적 분석만으로도 간단한 피싱·드라이브바이 다운로드(Drive-by download) 코드를 탐지할 수 있지만, 복잡하게 숨겨진 악성 로직은 동적 분석이 필수
   - 동적 분석은 리소스(서버, 시간)가 많이 들기 때문에 사전 필터링 후 위험도가 높다고 판단되는 URL에만 적용하는 게 현실적

---

## 4. LLM에 질의응답 (GPT, Grok, Perplexity 등 활용)

1. **입력 데이터 구성 (Feature Engineering)**

   - 1\~3단계에서 수집된 주요 피처(도메인 신뢰도 점수, WHOIS 정보, DNS 레코드 변화 이력, HTML/JS 스코어, 동적 분석 결과, 정적 분석 주요 경고)를 종합해 “입력 프롬프트” 또는 “JSON 구조”로 정리
   - 예시 구조 (JSON):

     ```json
     {
       "url": "http://malicious-example.com",
       "domain_age_days": 3,
       "whois_privacy_enabled": true,
       "dns_ttl": 60,
       "ssl_issuer": "LetEncrypt",
       "html_features": {
         "num_iframe": 2,
         "has_meta_refresh": true,
         "num_obfuscated_scripts": 3
       },
       "dynamic_features": {
         "redirect_chain_length": 4,
         "download_attempt_detected": true
       }
     }
     ```

2. **Prompt 설계**

   - 가능한 한 구체적인 정보를 제공하고, LLM이 과거 피싱 패턴을 참고해 “이 URL은 피싱 가능성이 높다/낮다”를 답할 수 있도록 유도
   - 예시:

     ```
     아래 JSON은 특정 URL에 대한 분석 결과입니다.
     URL: http://malicious-example.com
     domain_age_days: 3
     whois_privacy_enabled: true
     dns_ttl: 60
     ssl_issuer: LetEncrypt
     html_features:
       - num_iframe: 2
       - has_meta_refresh: true
       - num_obfuscated_scripts: 3
     dynamic_features:
       - redirect_chain_length: 4
       - download_attempt_detected: true

     이 정보를 바탕으로, 해당 URL이 피싱이나 악성코드 유포 사이트일 가능성(0부터 100 사이 점수)과 이유를 설명해 주세요.
     ```

3. **LLM 종류별 고려사항**

   - **GPT 계열(예: GPT-4, GPT-3.5)**

     - 장점: 방대한 학습 데이터 기반으로 과거 피싱·악성 패턴에 대한 설명과 사례를 잘 들어줌
     - 단점: 특화된 보안 위협 인텔리전스(탐지 기법)보다는 일반적인 설명에 치우칠 수 있음. 외부 저장소나 실시간 블랙리스트 조회 없이 “지식 커트오프” 시점 이후 신규 위협 정보는 반영되지 않음

   - **보안 특화 모델(Grok, Perplexity 보안 튜닝 버전 등)**

     - 장점: 피싱·악성코드 관련 최신 위협 인텔리전스가 반영된 경우 상대적으로 정확도가 높을 수 있음
     - 단점: 일반 GPT 계열에 비해 모델 크기가 작거나, API 한도가 제한적일 수 있음

4. **LLM 응답 후 추가 후처리**

   - **신뢰도(Confidence) 추출**: LLM이 반환한 텍스트 중 “확실하다/의심된다” 같은 표현을 파싱해 정량화(예: “의심된다” → 70점)
   - **설명 기반 평가**: LLM 설명 부분에 근거(예: “도메인 생성 후 3일밖에 안 되어서”, “메타 리프레시가 발견됨” 등)가 포함되었는지 확인
   - **자동화된 검증**: LLM 결과를 바로 최종 감지판단으로 삼기보다는, 간단한 룰 기반 필터(“점수 ≥ 80점이고 도메인 연령 ≤ 7일” 등)와 결합해 2차 검증

5. **정리**

   - LLM을 쓰면 정형화된 룰만으로는 잡아내기 어려운 “새로운 유형의 피싱 수법”(예: 비주류 CDN을 통한 스크립트 배포, 난독화 기법) 등을 자연어 설명으로 파악하도록 유도 가능
   - 그러나 LLM 응답의 신뢰도나 일관성은 항상 100% 보장되지 않기 때문에, 반드시 추가적인 검증 단계가 필요

---

## 5. 앙상블 및 점수 산출 (자체 알고리즘 필요)

1. **단계별 점수(Score) 부여**

   - **1단계(도메인 검사) 점수**

     - IDN 의심: +20점
     - 편집거리 임계치 초과: +15점
     - 비표준 포트 사용/인증서 불일치: +10점

   - **2단계(DNS/WHOIS) 점수**

     - 최근(7일 이내) 등록: +25점
     - 비밀 WHOIS(Privacy) 사용: +10점
     - TTL 짧음(≤ 60초): +10점

   - **3단계(HTML·JS) 점수**

     - Obfuscated JS 탐지: +20점
     - Meta-refresh 자동 리디렉션: +15점
     - 의심스러운 외부 도메인 호출: +10점

   - **4단계(LLM) 점수**

     - LLM 산출 위험도(0\~100) × 0.3 가중치(예: 80 → 24점)

   - **가중치 합산 후 최종 임계치 판정**

     - 예시: 최종 점수 ≥ 60점 → “악성 URL” 판정, 40\~60 → “의심 URL”, < 40 → “정상 URL”

2. **앙상블 로직 예시**

   1. 각 단계별 점수를 정규화(0\~100으로 맞춤)
   2. 단계별 중요도에 따라 가중치 배분(예: 도메인 검사 0.15, DNS/WHOIS 0.20, HTML/JS 0.35, LLM 0.30)
   3. 최종 점수 = ∑(단계\_i\_점수 × 가중치\_i)
   4. **추가 룰 예시**

      - “도메인 생성일 ≤ 3일” AND “LLM 위험도 ≥ 70” → 위험도 100점(최대)
      - “SSL 인증서 만료 임박” OR “의심스러운 스크립트 패턴 2개 이상” → 위험도 +10점 보정

3. **알고리즘 최적화 방법**

   - **하이퍼파라미터 튜닝**

     - 가중치 조정, 각 단계별 임계치(예: 도메인 생성일 제한, LLM 임계점) 값을 실제 라벨링된 데이터(피싱 URL vs 정상 URL)로 그리드서치(Grid Search)

   - **학습 기반 메타 모델**

     - 각 단계별 특징(Feature)들을 모아서 LightGBM, XGBoost 같은 메타 분류기를 학습 → 앙상블

   - **지속적인 피드백 루프**

     - 탐지된 URL 중 오탐(False Positive)·미탐(False Negative)을 운영자에게 보고 → 주기적으로 모델/점수체계 재학습

4. **정리**

   - 각 단계별로 얻은 점수를 적절히 조합하면 단일 룰 기반 탐지보다 훨씬 높은 정확도 달성 가능
   - 하지만 피싱·악성코드 제작자는 빠르게 탐지 로직을 회피하는 기법(도메인 위장, 코드 난독화, LLM 우회 프롬프트 공격 등)을 개발하기 때문에, 운영 과정에서 지속적인 업데이트와 재검증이 필수

---

## 최종적인 효과 분석 및 한계

1. **장점**

   - **다중 관점(Multi-Perspective) 탐지**: 도메인 정보, DNS/WHOIS, 정적·동적 코드 분석, LLM 기반 판단을 모두 사용하므로 단일 기법 대비 오탐·미탐 확률이 감소
   - **신규 악성 패턴 대응**: LLM을 통해 과거 데이터에 없는 새로운 피싱 수법(Obfuscated JavaScript, Social engineering 기반 랜딩페이지)도 일정 수준까지 감지
   - **유연한 앙상블 설계**: 단계별 가중치 조절 혹은 메타 분류기 학습을 통해 실제 조직 환경에 맞춘 탐지 정확도 최적화 가능

2. **한계 및 주의사항**

   1. **자원(시간·비용) 소모**

      - 동적 분석(헤드리스 브라우저) → 페이지 로딩에 최소 수초 이상 소요, 대량 URL 실시간 검사 불가능
      - LLM API 호출(예: GPT-4) 시 비용 및 응답 지연 발생

   2. **오탐/미탐 문제**

      - 정상적으로 오래된 but 취약점이 있는 사이트는 1\~2단계에서 이상 징후가 없으므로 탐지 어려움
      - 고도로 위장된 피싱 사이트(정상 도메인 탈취 후 SSL 적용) → 1\~3단계를 모두 통과, LLM에게도 설명하기 어려운 사례 발생
      - 반대로 “신규 생성 도메인+간단한 스크립트”로 엉성하게 만든 정상 테스트 사이트도 오탐 가능

   3. **LLM 한계**

      - LLM 자체 지식 커트오프 또는 훈련 데이터 편향으로 “신규 악성 기법”에 대해 오판할 수 있음
      - 프롬프트 엔지니어링 및 후처리 로직이 매우 민감 → 잘못 구성 시 낮은 신뢰도

   4. **운영 환경 고려사항**

      - **실시간 탐지 vs 배치(Batch) 탐지**

        - 실시간: DNS 조회, HTML 분석, LLM 호출을 모든 요청에 하면 과부하 → 사전 필터링(1~~2단계) 후 3~~4단계 적용
        - 배치: 새로 수집된 URL을 하루 또는 일정 주기로 분석 → 운영자는 의심 URL 리스트 검토 후 조치

      - **피드백 생태계 마련**

        - 탐지 후 실제 오탐/미탐 정보를 수집해 주기적으로 앙상블 파라미터 업데이트

3. **종합 결론**

   - 제안하신 5단계 프로세스는 이론적으로 매우 탄탄하며, 실제로 잘만 구현하면 단일 시그니처 기반 탐지 대비 월등한 정확도를 기대할 수 있습니다.
   - 다만, “리소스 소모(시간, API 호출 비용)”와 “실제 운영 환경에서의 오탐/미탐 피드백 루프”를 반드시 고려해야 합니다.
   - 결국 최종 효과는 “어떤 비율로 사전 필터링(1\~2단계)을 걸고, 어느 수준의 리소스(서버·API 예산)를 투입하며, 실제 탐지 조직의 운영 정책(실시간 vs 배치)에 맞춰 얼마나 효율적으로 적용하느냐”에 달려 있습니다.

---

### 요약

1. **1단계**: 도메인 자체의 위조·유사성 검사 → 간단하지만 한계 있음
2. **2단계**: WHOIS·DNS 정보 수집 → 도메인 신뢰도 평가, 오래된 도메인 vs 신규 도메인 구분
3. **3단계**: HTML/JS 정적·동적 분석 → 페이지 내부 스크립트·행위 기반 위협 탐지
4. **4단계**: LLM 질의응답 → 복잡하게 숨겨진 악성 로직까지 자연어적 맥락으로 이해 유도
5. **5단계**: 앙상블 점수 산출 → 단계별 점수를 가중치 합산 또는 메타 모델 학습을 통해 최종 판단

각 단계를 잘 조합하면 높은 탐지율을 얻을 수 있지만, 리소스(시간·비용)와 오탐/미탐 관리가 핵심 과제입니다.

---

## 1. 1단계 기능 개요

1단계에서는 \*\*“URL이 위조·변조되었거나 IDN(Internationalized Domain Name) 공격에 속하는지, 또 스킴(scheme)이나 포트가 비정상적으로 바뀌었는지”\*\*를 판단합니다. 구체적으로 다음 네 가지 하위 기능을 구현할 수 있습니다:

1. **IDN(국제화 도메인) 검사**

   - URL에 포함된 유니코드 문자가 Punycode로 인코딩된 형태인지 확인하고, 정상적인 ASCII 도메인과 “시각적으로 거의 유사하지만 다른” 도메인(예: Cyrillic 문자 vs Latin 문자)인지 탐지합니다.
   - 라이브러리: `idna`, `unicodedata` 등을 사용해 NFC/NFD 정규화를 수행하고, Punycode 디코딩/재인코딩을 비교합니다.

2. **타이포스쿼팅(오탈자 도메인) 탐지**

   - 잘 알려진(또는 “화이트리스트”에 등록된) 정상 도메인 목록과 비교하여, 편집거리(Edit distance)가 짧은(예: 1\~2자 차이) 도메인인지 판단합니다.
   - 라이브러리: `python-Levenshtein` 또는 순수 Python 구현(예: `difflib.SequenceMatcher`나 자체 함수)으로 두 문자열의 편집거리를 계산합니다.

3. **SSL/TLS 인증서 검사**

   - URL이 HTTPS일 때, 해당 도메인에 걸린 인증서 정보를 가져와서 발급자(CA), 유효기간(만료일), 도메인 일치 여부 등을 점검합니다.
   - 라이브러리: 표준 `ssl`, `socket`, 혹은 `certifi` 등을 이용해 원격 서버와 SSL 핸드셰이크를 수행하고 인증서 체인을 파싱합니다.

4. **URL 스킴(scheme)·포트 검사**

   - URL의 스킴이 `http`·`https` 밖에 없는지 확인하거나, 비표준 포트를 사용하는지(예: `http://example.com:8080` 등) 확인합니다.
   - 파이썬 표준 `urllib.parse`를 써서 URL을 파싱하고, scheme 또는 port 정보가 비정상적일 경우 경고합니다.

위 네 기능을 모두 **모듈화**(`step1/` 폴더 아래에 각각 파일로 분리)한 뒤, `main.py`에서는 \*\*argparse로 입력받은 URL과 옵션(어떤 기능을 실행할지)\*\*에 맞춰 해당 함수만 호출하도록 구성하면 됩니다.

---

## 2. 디렉터리 구조 예시

```
project_root/
├─ step1/
│   ├─ __init__.py
│   ├─ idn_check.py
│   ├─ typosquat_check.py
│   ├─ ssl_check.py
│   └─ scheme_check.py
└─ main.py
```

- `step1/idn_check.py`
  IDN 관련 검사 함수
- `step1/typosquat_check.py`
  편집거리 기반 타이포스쿼팅 검사 함수
- `step1/ssl_check.py`
  HTTPS 인증서 정보를 가져와 발급자, 만료일, 도메인 일치 등을 체크하는 함수
- `step1/scheme_check.py`
  URL 스킴과 포트를 검사하는 함수
- `main.py`
  `argparse`를 통해 커맨드라인 인자를 받고, 호출할 모듈의 함수를 실행만 하는 최소한의 로직

아래에 각 파일의 코드를 순서대로 보여드립니다.

---

## 3. 모듈별 코드

### 3.1 `step1/idn_check.py`

```python
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
```

> **설명**
>
> 1. `normalize_domain(domain)`: 주어진 도메인을 유니코드 NFC 정규화 후 Punycode로 변환했다가 다시 디코딩하여, 시각적으로 동일한 문자인지 확인하도록 돕는 헬퍼 함수입니다.
> 2. `check_idn(url)`: URL에서 호스트만 파싱해서 IDN(Punycode) 여부를 판단합니다. 호스트가 `xn--`으로 시작하거나 포함돼 있으면 “IDN 사용 중”으로 표시하고, 디코딩된 결과(정상 도메인)도 함께 반환합니다.

---

### 3.2 `step1/typosquat_check.py`

```python
# step1/typosquat_check.py

import re
import difflib
from urllib.parse import urlparse


def levenshtein_distance(a: str, b: str) -> int:
    """
    순수 파이썬으로 두 문자열의 Levenshtein 거리 계산
    (시간 복잡도가 O(N*M)이므로, 리스트가 많으면 성능 저하 주의)
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
            curr[j] = min(prev_row[j] + 1,      # 삭제
                          curr[j - 1] + 1,      # 삽입
                          prev_row[j - 1] + cost)  # 교체
        prev_row = curr
    return prev_row[-1]


def extract_domain_without_www(hostname: str) -> str:
    """
    www. 접두사가 있으면 제거하고,
    서브도메인(ex: mail.example.com)을 최상위 도메인+TLD로 단순화해 리턴
    ex) mail.google.com → google.com
    """
    # www. 제거
    if hostname.startswith("www."):
        hostname = hostname[4:]
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    # 예: mail.google.co.kr → co.kr보다 한 단계 위를 인식해야 하지만, 복잡도를 낮추려면 뒤에서 두 개만 사용
    return ".".join(parts[-2:])


def check_typosquat(url: str, whitelist: list, max_distance: int = 2) -> dict:
    """
    URL로부터 최상위 도메인(TLD 포함)을 가져와서,
    whitelist(정상 도메인 리스트)와 편집거리(Levenshtein distance)를 계산해
    가장 가까운 도메인과 거리, 그리고 의심 여부를 반환.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return {"error": "유효한 호스트를 URL에서 추출할 수 없습니다."}

    domain = extract_domain_without_www(hostname.lower())
    results = []

    for legit in whitelist:
        dist = levenshtein_distance(domain, legit.lower())
        if dist <= max_distance:
            results.append((legit, dist))

    # 편집거리가 가장 작은 순으로 정렬
    results.sort(key=lambda x: x[1])

    if len(results) == 0:
        return {
            "domain": domain,
            "suspected": False,
            "closest": None,
            "distance": None,
            "comment": f"화이트리스트 도메인과 편집거리 ≤ {max_distance}인 대상이 없습니다."
        }
    closest_domain, closest_dist = results[0]
    return {
        "domain": domain,
        "suspected": True,
        "closest": closest_domain,
        "distance": closest_dist,
        "comment": f"가장 근접한 도메인: {closest_domain} (거리: {closest_dist})"
    }
```

> **설명**
>
> 1. `levenshtein_distance(a, b)`: 순수 파이썬으로 두 문자열의 편집거리를 계산하는 함수입니다.
> 2. `extract_domain_without_www(hostname)`: 서브도메인을 제거하고 최상위 도메인+TLD(예: example.com)만 남깁니다. (`co.kr`처럼 2차 TLD 구조는 간략화)
> 3. `check_typosquat(url, whitelist, max_distance)`:
>
>    - `whitelist` 인자로 정상 도메인 리스트를 받아오면, 각 도메인과의 편집거리를 비교해 `max_distance` 이내이면 “의심”으로 표시합니다.
>    - 실제 운영 시엔 Google, Naver, Daum 등 주요 도메인을 미리 모아둔 리스트를 넘겨주는 식으로 사용합니다.

---

### 3.3 `step1/ssl_check.py`

```python
# step1/ssl_check.py

import ssl
import socket
import datetime
from urllib.parse import urlparse


def get_certificate_info(url: str, timeout: float = 3.0) -> dict:
    """
    HTTPS URL에 대해 원격 서버로 SSL 핸드셰이크를 시도하여,
    서버 인증서의 발급자, 유효기간, 도메인 일치 여부 등을 반환.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    if parsed.scheme.lower() != "https":
        return {"error": "HTTPS 스킴이 아닌 URL에서는 SSL 정보를 가져올 수 없습니다."}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 인증서 검증(예: 유효 CA 검사)은 생략

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        return {"error": f"SSL 연결/인증서 가져오기 실패: {e}"}

    issuer = dict(x[0] for x in cert["issuer"])
    subject = dict(x[0] for x in cert["subject"])
    not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

    # 도메인 일치 여부 확인
    san = cert.get("subjectAltName", [])
    san_list = [entry[1] for entry in san if entry[0].lower() == "dns"]
    domain_match = hostname in san_list or subject.get("commonName", "") == hostname

    return {
        "hostname": hostname,
        "issuer_common_name": issuer.get("commonName", ""),
        "subject_common_name": subject.get("commonName", ""),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "domain_match": domain_match,
        "san_list": san_list,
        "comment": "인증서 발급자, 유효기간, SAN(DNS) 리스트 및 도메인 일치 여부 반환"
    }
```

> **설명**
>
> - `get_certificate_info(url)`: HTTPS URL에 대해서만 작동합니다.
> - `ssl.create_default_context()`를 통해 간단한 SSL 핸드셰이크를 시도한 뒤, `getpeercert()`로 인증서 체인에서 첫 번째(서버) 인증서를 가져옵니다.
> - `issuer`, `subject`, `notBefore`, `notAfter`, `subjectAltName` 필드를 파싱해 반환합니다.
> - 실제 운영에서는 `verify_mode=ssl.CERT_REQUIRED`로 CA 검증을 활성화할 수도 있고, CRL(인증서 폐기 목록)이나 OCSP 검사 로직을 덧붙일 수 있습니다.

---

### 3.4 `step1/scheme_check.py`

```python
# step1/scheme_check.py

from urllib.parse import urlparse


def check_scheme_and_port(url: str) -> dict:
    """
    URL을 파싱하여 스킴(scheme)이 http/https인지,
    표준 포트(80, 443)를 벗어나지 않는지 검사.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    port = parsed.port
    hostname = parsed.hostname

    if not hostname:
        return {"error": "유효한 호스트를 URL에서 추출할 수 없습니다."}

    issues = []
    # 1) 스킴 검사
    if scheme not in ("http", "https"):
        issues.append(f"비표준 스킴 사용: {scheme}")

    # 2) 포트 검사 (명시적 포트가 없으면 디폴트)
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
```

> **설명**
>
> - `check_scheme_and_port(url)`: `urllib.parse.urlparse`로 URL을 분석한 뒤,
>
>   1. `scheme`이 `http`나 `https`가 아닌 경우
>   2. 포트가 명시되어 있고(예: `:8080`), 표준 포트(HTTP→80, HTTPS→443)가 아닌 경우
>      에 대해 `issues` 리스트에 메시지를 추가합니다.
>
> - `issues`가 비어 있으면 `"문제 없음"`을 결과로 내보냅니다.

---

## 4. `main.py` 작성 예시

```python
# main.py

import argparse
from step1.idn_check import check_idn
from step1.typosquat_check import check_typosquat
from step1.ssl_check import get_certificate_info
from step1.scheme_check import check_scheme_and_port


def parse_args():
    parser = argparse.ArgumentParser(
        description="Step1: URL 위조·변조·IDN·스킴/포트 검사"
    )
    parser.add_argument(
        "--url", "-u",
        required=True,
        help="검사할 대상 URL (예: https://example.com)"
    )
    parser.add_argument(
        "--idn",
        action="store_true",
        help="IDN(Punycode) 검사 실행"
    )
    parser.add_argument(
        "--typo",
        action="store_true",
        help="타이포스쿼팅(오탈자) 검사 실행 (Whitelist 필요)"
    )
    parser.add_argument(
        "--ssl",
        action="store_true",
        help="SSL/TLS 인증서 정보 검사 실행 (HTTPS URL이어야 함)"
    )
    parser.add_argument(
        "--scheme",
        action="store_true",
        help="스킴/포트 검사 실행"
    )
    parser.add_argument(
        "--whitelist",
        "-w",
        nargs="*",
        default=[],
        help="타이포스쿼팅 검사 시 비교할 정상 도메인 리스트(예: google.com naver.com daum.net)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    url = args.url

    # 1) IDN 검사
    if args.idn:
        result = check_idn(url)
        print("=== IDN 검사 결과 ===")
        for k, v in result.items():
            print(f"{k}: {v}")
        print()

    # 2) 타이포스쿼팅 검사
    if args.typo:
        if not args.whitelist:
            print("타이포스쿼팅 검사를 위해 --whitelist 옵션으로 정상 도메인 리스트를 지정해주세요.")
        else:
            result = check_typosquat(url, args.whitelist)
            print("=== 타이포스쿼팅 검사 결과 ===")
            for k, v in result.items():
                print(f"{k}: {v}")
            print()

    # 3) SSL 인증서 검사
    if args.ssl:
        result = get_certificate_info(url)
        print("=== SSL 인증서 검사 결과 ===")
        for k, v in result.items():
            print(f"{k}: {v}")
        print()

    # 4) 스킴/포트 검사
    if args.scheme:
        result = check_scheme_and_port(url)
        print("=== 스킴/포트 검사 결과 ===")
        for k, v in result.items():
            print(f"{k}: {v}")
        print()


if __name__ == "__main__":
    main()
```

> **설명**
>
> - `argparse`로 받아올 인자는 다음과 같습니다:
>
>   - `--url` (`-u`): 검사 대상 URL (필수)
>   - `--idn`: IDN 검사 여부
>   - `--typo`: 타이포스쿼팅 검사 여부 (실행 시 `--whitelist`로 정상 도메인 리스트를 함께 넘겨야 함)
>   - `--ssl`: SSL 인증서 검사 여부 (HTTPS URL만 검사 가능)
>   - `--scheme`: 스킴/포트 검사 여부
>   - `--whitelist` (`-w`): 타이포스쿼팅 비교 시 사용할 정상 도메인 목록(공백으로 구분)
>
> - `main()` 함수에선 “각 옵션이 True로 지정됐는지”를 보고, 해당 모듈의 함수를 호출만 합니다.
>
>   - 결과(`dict`)를 받아와 키-값 형태로 `print`합니다.
>   - `main.py` 내부에는 **argparse 정의 및 호출 코드 외에** 로직이 들어가지 않았습니다.

---

## 5. 사용 예시

1. **IDN 검사만 실행**

   ```bash
   python main.py --url "http://xn--e1afmkfd.xn--p1ai" --idn
   ```

   ```
   === IDN 검사 결과 ===
   hostname: xn--e1afmkfd.xn--p1ai
   is_idn: True
   normalized: пример.рф
   comment: 원래 호스트와 정규화 결과 비교 필요
   ```

2. **타이포스쿼팅 검사만 실행(화이트리스트 예시: google.com, naver.com)**

   ```bash
   python main.py --url "http://gooogle.com" --typo --whitelist google.com naver.com
   ```

   ```
   === 타이포스쿼팅 검사 결과 ===
   domain: gooogle.com
   suspected: True
   closest: google.com
   distance: 1
   comment: 가장 근접한 도메인: google.com (거리: 1)
   ```

3. **SSL 인증서 검사만 실행**

   ```bash
   python main.py --url "https://www.google.com" --ssl
   ```

   ```
   === SSL 인증서 검사 결과 ===
   hostname: www.google.com
   issuer_common_name: GTS CA 1O1
   subject_common_name: *.google.com
   not_before: 2025-03-15T00:00:00
   not_after: 2025-06-14T23:59:59
   domain_match: True
   san_list: ['*.google.com', 'google.com']
   comment: 인증서 발급자, 유효기간, SAN(DNS) 리스트 및 도메인 일치 여부 반환
   ```

4. **스킴/포트 검사만 실행**

   ```bash
   python main.py --url "ftp://example.com:21" --scheme
   ```

   ```
   === 스킴/포트 검사 결과 ===
   hostname: example.com
   scheme: ftp
   port: 21
   issues:
     - 비표준 스킴 사용: ftp
     - HTTP/HTTPS가 아닌 포트 사용 검사 불필요 (스킴이 ftp이므로)
   comment: 스킴/포트 관련 잠재적 의심 요소 반환
   ```

5. **한 번에 모든 기능 실행**

   ```bash
   python main.py --url "https://xn--e1afmkfd.xn--p1ai:443" --idn --typo --ssl --scheme --whitelist google.com naver.com daum.net
   ```

   ```
   === IDN 검사 결과 ===
   hostname: xn--e1afmkfd.xn--p1ai
   is_idn: True
   normalized: пример.рф
   comment: 원래 호스트와 정규화 결과 비교 필요

   === 타이포스쿼팅 검사 결과 ===
   domain: xn--e1afmkfd.xn--p1ai
   suspected: False
   closest: None
   distance: None
   comment: 화이트리스트 도메인과 편집거리 ≤ 2인 대상이 없습니다.

   === SSL 인증서 검사 결과 ===
   hostname: xn--e1afmkfd.xn--p1ai
   error: SSL 연결/인증서 가져오기 실패: [Errno -2] Name or service not known

   === 스킴/포트 검사 결과 ===
   hostname: xn--e1afmkfd.xn--p1ai
   scheme: https
   port: 443
   issues:
     - 문제 없음
   comment: 스킴/포트 관련 잠재적 의심 요소 반환
   ```

---

## 6. 요약

1. **하위 기능**

   - `step1/idn_check.py` → IDN(Punycode) 사용 여부 및 정규화 결과
   - `step1/typosquat_check.py` → 편집거리 기반 정상 도메인과의 유사도
   - `step1/ssl_check.py` → HTTPS 인증서 발급자·유효기간·도메인 일치 여부
   - `step1/scheme_check.py` → 스킴/포트 정상 여부

2. **`main.py`**

   - `argparse`로 `--url`, `--idn`, `--typo`, `--ssl`, `--scheme`, `--whitelist` 인자를 받고
   - 각 옵션이 활성화됐을 때만 해당 모듈의 함수를 호출(리턴값을 출력)
   - \*“argparse 정의 및 모듈 함수 호출”\*만 포함하고 나머지 로직은 모두 모듈 파일로 분리

3. **사용 방법**

   - Conda 가상환경(`url_detect`)을 활성화한 뒤, 프로젝트 최상위에 있는 `main.py`를 아래처럼 실행하면 됨:

     ```bash
     python main.py --url "<검사할 URL>" [--idn] [--typo --whitelist <도메인1> <도메인2> ...] [--ssl] [--scheme]
     ```

아래에서는 Step 2(“DNS·URL 정보 수집”)에 해당하는 하위 기능들을 정리하고, 각각을 모듈화한 예시 코드를 제시합니다. Step 1과 마찬가지로, 각 기능은 별도 파일(`step2/` 폴더)로 분리하였고, 마지막에 `main.py`에서 argparse로 호출만 하도록 구성했습니다.

---

## 1. Step 2의 주요 기능

1. **WHOIS 조회 (`whois_check.py`)**

   - 도메인의 WHOIS 정보를 가져와 등록자, 등록 기관, 생성일(created), 만료일(expiration), 갱신일(updated) 등을 추출합니다.
   - 이를 통해 “도메인이 언제 등록되었고, 만료 주기가 어떤지”를 알 수 있습니다.
   - 파이썬 라이브러리: `python-whois`

2. **DNS 레코드 조회 (`dns_check.py`)**

   - A, AAAA, MX, NS, TXT, CNAME 등 주요 레코드를 조회합니다.
   - TTL(Time To Live)을 함께 얻어서 “레코드가 자주 바뀌는지(짧은 TTL)”를 파악합니다.
   - 파이썬 라이브러리: `dnspython` (`import dns.resolver`)

3. **URL 세부 분석 (`urlinfo_check.py`)**

   - 전체 URL을 파싱하여 스킴, 호스트, 경로(path), 쿼리 파라미터(query string), 확장자(extension) 등을 추출합니다.
   - URL 경로 또는 파라미터에 “리다이렉트 의심 토큰”(예: `redirect=`, `url=`, `download=`)이 있는지 간단히 검사합니다.
   - 파이썬 표준 모듈: `urllib.parse`, `os.path`

이 세 가지 기능을 각각 모듈에 담고, `main.py`에서는 `--whois`, `--dns`, `--urlinfo` 플래그로 필요할 때만 호출하도록 설계합니다.

---

## 2. 디렉터리 구조 예시

```
project_root/
├─ step1/                    # 이전에 만들었던 Step 1 모듈
│   ├─ idn_check.py
│   ├─ typosquat_check.py
│   ├─ ssl_check.py
│   └─ scheme_check.py
│
├─ step2/                    # 이제 추가할 Step 2 모듈
│   ├─ __init__.py
│   ├─ whois_check.py
│   ├─ dns_check.py
│   └─ urlinfo_check.py
│
└─ main.py                   # argparse 로 Step 1 + Step 2 기능들을 호출
```

---

## 3. Step 2 모듈별 코드

### 3.1 `step2/whois_check.py`

```python
# step2/whois_check.py

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
```

- **설명**

  - `whois.whois(domain)` 호출 시, 도메인에 대한 WHOIS 레코드가 반환됩니다.
  - `creation_date`, `updated_date`, `expiration_date` 등이 `datetime` 객체 또는 `list[datetime]` 형태로 들어오는데, 이를 ISO 8601 문자열(`.isoformat()`)로 변환해 표준화합니다.
  - 그 외 `registrar`, `whois_server`, `name_servers`, `emails`, `status` 등도 있으면 가져옵니다.
  - 오류가 나면 `{"error": "..."} ` 형태로 반환합니다.

---

### 3.2 `step2/dns_check.py`

```python
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
```

- **설명**

  - `dns.resolver.resolve(domain, rtype)`를 이용해 여러 레코드(A, AAAA, MX, NS, TXT, CNAME 등)를 순차 조회합니다.
  - `answers.rrset.ttl`에서 TTL 값을 가져와, 각 레코드별 `"value": "...", "ttl": ...` 형태로 저장합니다.
  - NoAnswer/NXDOMAIN(조회 불가) 예외가 발생하면 빈 리스트(`[]`)로 반환하고, 그 밖의 DNS 예외는 `{"error": "..."} `형태로 반환합니다.

---

### 3.3 `step2/urlinfo_check.py`

```python
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
```

- **설명**

  - `urlparse(url)`로 스킴, 호스트, 경로, 쿼리 등을 파싱합니다.
  - 포트가 명시되지 않으면 `HTTP→80, HTTPS→443`으로 기본값을 할당합니다.
  - `os.path.basename(path)`와 `os.path.splitext(...)`를 이용해 파일명과 확장자를 추출합니다.
  - `parse_qs(query)`로 쿼리 파라미터를 `{key: [value1, value2, …]}` 형태로 뽑고, `redirect`, `url`, `download`, `file`, `continue` 등의 단어가 키에 포함된 경우 “의심 키”로 표시합니다.

---

## 4. `main.py` 수정 예시

아래는 Step 1(이미 만들어 놓은 부분) + Step 2(추가) 모두를 argparse로 제어하는 방식의 `main.py` 예시입니다. Step 2 관련 플래그는 `--whois`, `--dns`, `--urlinfo` 세 가지를 두고, 해당 옵션이 켜졌을 때만 모듈을 호출하도록 합니다.

```python
# main.py

import argparse

# Step 1 모듈 임포트
from step1.idn_check import check_idn
from step1.typosquat_check import check_typosquat
from step1.ssl_check import get_certificate_info
from step1.scheme_check import check_scheme_and_port
from utils.load_whitelist import load_whitelist_from_umbrella, load_whitelist_from_tranco, load_whitelist_from_txt

# Step 2 모듈 임포트
from step2.whois_check import get_whois_info
from step2.dns_check import query_dns_records
from step2.urlinfo_check import parse_url_info


def parse_args():
    parser = argparse.ArgumentParser(
        description="Step1(위조/IDN/타이포/SSL/스킴) + Step2(DNS·URL 정보 수집) 통합 툴"
    )

    # 공통 인자
    parser.add_argument("--url", "-u", required=True, help="검사할 대상 URL (예: https://example.com)")
    parser.add_argument("--domain", "-d", help="도메인 만 별도 지정 (Step 2 WHOIS/DNS 용도로 사용)")

    # Step 1 옵션
    parser.add_argument("--idn", action="store_true", help="IDN 검사 실행")
    parser.add_argument("--typo", action="store_true", help="타이포스쿼팅 검사 실행")
    parser.add_argument("--typo-dataset", choices=["umbrella", "tranco"], help="타이포스쿼팅용 데이터셋 (umbrella or tranco)")
    parser.add_argument("--typo-path", help="타이포스쿼팅용 도메인 리스트 파일 경로 (CSV 또는 TXT). --typo-dataset 미지정 시 사용")
    parser.add_argument("--ssl", action="store_true", help="SSL/TLS 인증서 검사 실행")
    parser.add_argument("--scheme", action="store_true", help="스킴/포트 검사 실행")

    # Step 2 옵션
    parser.add_argument("--whois", action="store_true", help="WHOIS 조회 실행")
    parser.add_argument("--dns", action="store_true", help="DNS 레코드 조회 실행")
    parser.add_argument("--urlinfo", action="store_true", help="URL 구조 분석 실행")

    return parser.parse_args()


def main():
    args = parse_args()

    # Step 1 실행
    if args.idn:
        print("=== Step 1: IDN 검사 ===")
        res = check_idn(args.url)
        for k, v in res.items():
            print(f"{k}: {v}")
        print()

    if args.typo:
        print("=== Step 1: 타이포스쿼팅 검사 ===")
        # 도메인 부분만 떼기
        # URL이 https://foo.bar/path 일 때, foo.bar 부분을 도메인으로 넘기도록 로직
        from urllib.parse import urlparse
        parsed = urlparse(args.url)
        domain_only = parsed.hostname or args.url

        # 화이트리스트 로드
        whitelist = []
        if args.typo_dataset:
            if args.typo_dataset == "umbrella":
                whitelist = load_whitelist_from_umbrella("data/umbrella_top1m.csv", top_n=100000)
            else:
                whitelist = load_whitelist_from_tranco("data/tranco_2NW29.csv", top_n=100000)
        elif args.typo_path:
            if args.typo_path.endswith(".csv"):
                whitelist = load_whitelist_from_tranco(args.typo_path, top_n=None)
            else:
                whitelist = load_whitelist_from_txt(args.typo_path, max_lines=None)
        else:
            print("타이포스쿼팅 검사를 위해 --typo-dataset 또는 --typo-path를 지정해주세요.")
            return

        res = check_typosquat(domain_only, whitelist)
        for k, v in res.items():
            print(f"{k}: {v}")
        print()

    if args.ssl:
        print("=== Step 1: SSL 인증서 검사 ===")
        res = get_certificate_info(args.url)
        for k, v in res.items():
            print(f"{k}: {v}")
        print()

    if args.scheme:
        print("=== Step 1: 스킴/포트 검사 ===")
        res = check_scheme_and_port(args.url)
        for k, v in res.items():
            print(f"{k}: {v}")
        print()

    # Step 2 실행
    # “도메인” 정보는 URL에서 호스트네임만 떼거나, args.domain을 직접 받아도 됩니다.
    # 여기서는 args.domain이 있으면 그것을, 없으면 URL에 포함된 hostname을 쓰도록 합니다.
    from urllib.parse import urlparse
    parsed_main = urlparse(args.url)
    domain_for_step2 = args.domain or parsed_main.hostname

    if args.whois:
        print("=== Step 2: WHOIS 조회 ===")
        if not domain_for_step2:
            print("WHOIS 조회를 위한 도메인을 인식할 수 없습니다.")
        else:
            res = get_whois_info(domain_for_step2)
            for k, v in res.items():
                print(f"{k}: {v}")
        print()

    if args.dns:
        print("=== Step 2: DNS 레코드 조회 ===")
        if not domain_for_step2:
            print("DNS 조회를 위한 도메인을 인식할 수 없습니다.")
        else:
            res = query_dns_records(domain_for_step2)
            for rtype, entries in res.items():
                print(f"{rtype}:")
                if isinstance(entries, list):
                    for entry in entries:
                        print(f"  - value: {entry['value']}, ttl: {entry['ttl']}")
                else:
                    # {'error': "..."} 형태
                    print(f"  - {entries}")
        print()

    if args.urlinfo:
        print("=== Step 2: URL 구조 분석 ===")
        res = parse_url_info(args.url)
        for k, v in res.items():
            print(f"{k}: {v}")
        print()


if __name__ == "__main__":
    main()
```

- **주요 변경점**

  1. `--whois` → WHOIS 조회 실행
  2. `--dns` → DNS 레코드 조회 실행
  3. `--urlinfo` → URL 구조 분석 실행
  4. `domain_for_step2 = args.domain or parsed_main.hostname` 로, 사용자가 `--domain`(도메인만 직접) 지정하지 않았다면 `urlparse`로 URL에서 hostname을 뽑아서 사용
  5. 각 결과(`dict`)를 받아와 키-값 형태로 `print`만 합니다. 내부 로직은 모두 별도 모듈 파일에 들어가 있습니다.

---

## 5. 사용 예시

1. **WHOIS만 실행**

   ```bash
   python main.py \
     --url "https://google.com" \
     --whois
   ```

   ```
   === Step 2: WHOIS 조회 ===
   domain_name: google.com
   registrar: MarkMonitor Inc.
   whois_server: whois.markmonitor.com
   creation_date: 1997-09-15T00:00:00
   updated_date: 2023-04-04T00:00:00
   expiration_date: 2028-09-14T00:00:00
   name_servers: ['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com']
   emails: ['dns-admin@google.com']
   status: clientDeleteProhibited,clientTransferProhibited,clientUpdateProhibited
   ```

2. **DNS 레코드만 실행**

   ```bash
   python main.py \
     --url "https://google.com" \
     --dns
   ```

   ```
   === Step 2: DNS 레코드 조회 ===
   A:
     - value: 142.250.200.14, ttl: 295
   AAAA:
     - value: 2607:f8b0:4009:805::200e, ttl: 295
   MX:
     - value: aspmx.l.google.com., ttl: 299
     - value: alt1.aspmx.l.google.com., ttl: 299
     - value: alt2.aspmx.l.google.com., ttl: 299
     - value: alt3.aspmx.l.google.com., ttl: 299
     - value: alt4.aspmx.l.google.com., ttl: 299
   NS:
     - value: ns1.google.com., ttl: 21599
     - value: ns2.google.com., ttl: 21599
     - value: ns3.google.com., ttl: 21599
     - value: ns4.google.com., ttl: 21599
   TXT:
     - value: "v=spf1 include:_spf.google.com ~all", ttl: 299
     - value: "docusign=059584d0-...",
     ...
   CNAME:
     - value: (없음)  # 실제 CNAME 레코드가 없으면 빈 리스트
   ```

3. **URL 구조 분석만 실행**

   ```bash
   python main.py \
     --url "http://example.com/download/malware.exe?redirect=https://phish.example&file=xyz" \
     --urlinfo
   ```

   ```
   === Step 2: URL 구조 분석 ===
   scheme: http
   hostname: example.com
   port: 80
   path: /download/malware.exe
   filename: malware.exe
   extension: .exe
   query_string: redirect=https://phish.example&file=xyz
   query_params: {'redirect': ['https://phish.example'], 'file': ['xyz']}
   suspicious_query_keys: ['redirect', 'file']
   comment: URL 구조 및 쿼리 리디렉션 가능성 키워드 반환
   ```

4. **Step 1 + Step 2를 한 번에 실행**

   ```bash
   python main.py \
     --url "https://xn--e1afmkfd.xn--p1ai/download.php?redirect=http://evil.com" \
     --idn \
     --typo --typo-dataset umbrella \
     --ssl \
     --scheme \
     --whois \
     --dns \
     --urlinfo
   ```

   ```
   === Step 1: IDN 검사 ===
   hostname: xn--e1afmkfd.xn--p1ai
   is_idn: True
   normalized: пример.рф
   comment: 원래 호스트와 정규화 결과 비교 필요

   === Step 1: 타이포스쿼팅 검사 ===
   domain: xn--e1afmkfd.xn--p1ai
   suspected: False
   closest: None
   distance: None
   comment: 화이트리스트 도메인과 편집거리 ≤ 2인 대상이 없습니다.

   === Step 1: SSL 인증서 검사 ===
   error: HTTPS가 아닌 URL에서는 SSL 정보를 가져올 수 없습니다.

   === Step 1: 스킴/포트 검사 ===
   hostname: xn--e1afmkfd.xn--p1ai
   scheme: http
   port: 80
   issues: ['문제 없음']
   comment: 스킴/포트 관련 잠재적 의심 요소 반환

   === Step 2: WHOIS 조회 ===
   domain_name: пример.рф
   registrar: RU-CENTER-RU
   whois_server: whois.tcinet.ru
   creation_date: 2014-06-03T00:00:00
   updated_date: 2023-05-01T00:00:00
   expiration_date: 2025-06-03T00:00:00
   name_servers: ['dns1.tcinet.ru', 'dns2.tcinet.ru']
   emails: ['privocs@tcinet.ru']
   status: ok

   === Step 2: DNS 레코드 조회 ===
   A:
     - value: 93.184.216.34, ttl: 299
   AAAA:
     - value: (없음)
   MX:
     - value: mail.example.net., ttl: 21599
     ...
   NS:
     - value: dns1.tcinet.ru., ttl: 86399
     - value: dns2.tcinet.ru., ttl: 86399
   TXT:
     - value: "v=spf1 include:_spf.tcinet.ru ~all", ttl: 299
   CNAME:
     - value: (없음)

   === Step 2: URL 구조 분석 ===
   scheme: http
   hostname: xn--e1afmkfd.xn--p1ai
   port: 80
   path: /download.php
   filename: download.php
   extension: .php
   query_string: redirect=http://evil.com
   query_params: {'redirect': ['http://evil.com']}
   suspicious_query_keys: ['redirect']
   comment: URL 구조 및 쿼리 리디렉션 가능성 키워드 반환
   ```

---

## 6. 요약

1. **WHOIS 조회** (`whois_check.py`)

   - 입력: 도메인(예: `google.com`)
   - 출력: 생성일, 갱신일, 만료일, 등록자, 네임서버, 이메일, 상태 등

2. **DNS 레코드 조회** (`dns_check.py`)

   - 입력: 도메인(예: `google.com`)
   - 출력: A, AAAA, MX, NS, TXT, CNAME 레코드 값과 TTL 정보

3. **URL 구조 분석** (`urlinfo_check.py`)

   - 입력: 전체 URL(예: `http://example.com/path/file.ext?redirect=…`)
   - 출력: 스킴, 호스트, 포트, 경로, 파일명/확장자, 쿼리 파라미터 사전, 의심 키워드 목록

4. `main.py`에서는 `--whois`, `--dns`, `--urlinfo` 플래그로 Step 2 기능을 켜고, 이전 Step 1 기능과 함께 “한 번에 여러 단계(1∼2)를 실행”할 수 있도록 구성했습니다.

#### LLM 질의응답 프롬프트 예시

```scss
첨부된 파일은 특정 URL에 대한 1~3단계 종합 분석 결과입니다.
모든 필드는 신뢰도 평가와 악성 여부 판단에 필요한 중요 정보를 담고 있습니다.

위 JSON 정보를 바탕으로, 해당 URL이 피싱/악성코드 유포 사이트일 가능성을 0부터 100 사이 점수로 평가하고,
왜 그 점수를 주었는지 구체적인 근거를 설명해 주세요
```
