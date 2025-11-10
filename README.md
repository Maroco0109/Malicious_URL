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

#### LLM 질의응답 프롬프트 예시

```scss
첨부된 파일은 특정 URL에 대한 1~3단계 종합 분석 결과입니다.
모든 필드는 신뢰도 평가와 악성 여부 판단에 필요한 중요 정보를 담고 있습니다.

위 JSON 정보를 바탕으로, 해당 URL이 피싱/악성코드 유포 사이트일 가능성을 0부터 100 사이 점수로 평가하고,
왜 그 점수를 주었는지 구체적인 근거를 설명해 주세요
```

---

### 실행 과정

1. 환경 설정

```bash
pip install -r requirements.txt
```

> 타이포스쿼팅 모듈은 등록 도메인을 정규화하기 위해 `publicsuffix2`를 사용하며 멀티 레이블 TLD에서도 Tranco 후보만 비교합니다.

2. URL 전처리 과정 실행

```bash
python main.py --url "{URL}" --idn --typo --typo-dataset tranco --ssl --scheme --whois --dns --urlinfo --static --dynamic --export-json
```

3. LLM API Call

```bash
# API Key 등록
export OPENAI_API_KEY="sk-{your api key}"
```

```bash
python call_llm_from_json.py {result file}
```

---

## 사용 방법 (Korean Usage Guide)

### 1. 환경 설정

먼저 필요한 패키지를 설치합니다:

```bash
pip install -r requirements.txt
```

### 2. URL 분석 실행

악성 URL을 분석하려면 다음 명령어를 사용합니다:

```bash
python main.py --url "{분석할 URL}" --idn --typo --typo-dataset tranco --ssl --scheme --whois --dns --urlinfo --static --dynamic --export-json
```

**옵션 설명:**
- `--url` 또는 `-u`: 분석할 대상 URL (필수)
- `--idn`: IDN(국제화 도메인 이름) 검사 수행
- `--typo`: 타이포스쿼팅 검사 수행 (`publicsuffix2`로 등록 도메인을 정규화하고 길이 기반 후보만 비교)
- `--typo-dataset tranco`: Tranco 상위 도메인 리스트 사용 (data/tranco_2NW29.csv)
- `--typo-path`: 사용자 지정 화이트리스트 파일 경로
- `--ssl`: SSL/TLS 인증서 검사
- `--scheme`: URL 스킴 및 포트 검사
- `--whois`: WHOIS 도메인 정보 조회
- `--dns`: DNS 레코드 조회
- `--urlinfo`: URL 구조 분석
- `--static`: 정적 HTML/JS 분석
- `--dynamic`: 동적 브라우저 분석 (헤드리스 Chrome 필요)
- `--export-json`: 결과를 JSON 파일로 저장 (도메인 이름 기반 자동 생성)

### 3. 실제 사용 예시

악성 사이트 분석 예시:

```bash
python main.py --url "http://www.824555.com/app/member/SportOption.php?uid=guest&langx=gb" --idn --typo --typo-dataset tranco --ssl --scheme --whois --dns --urlinfo --static --dynamic --export-json
```

위 명령어는 자동으로 `url_examine/824555_com_20250110_123456_results.json` 형식의 파일을 생성합니다.

피싱 의심 사이트 분석 예시 (Google Docs 위장):

```bash
python main.py --url "https://docs.google.com/spreadsheet/viewform?formkey=dGg2Z1lCUHlSdjllTVNRUW50TFIzSkE6MQ" --idn --typo --typo-dataset tranco --ssl --scheme --whois --dns --urlinfo --static --dynamic --export-json
```

위 명령어는 자동으로 `url_examine/docs_google_com_20250110_123456_results.json` 형식의 파일을 생성합니다.

정상 사이트 분석 예시:

```bash
python main.py --url "https://www.google.com" --idn --typo --typo-dataset tranco --ssl --scheme --whois --dns --urlinfo --static --dynamic --export-json
```

위 명령어는 자동으로 `url_examine/google_com_20250110_123456_results.json` 형식의 파일을 생성합니다.

### 4. LLM 분석 실행

OpenAI API 키를 설정합니다:

```bash
# Windows (PowerShell)
$env:OPENAI_API_KEY="sk-{your api key}"

# Windows (CMD)
set OPENAI_API_KEY=sk-{your api key}

# Linux/Mac
export OPENAI_API_KEY="sk-{your api key}"
```

생성된 JSON 파일을 LLM에 전달하여 최종 위험도 평가:

```bash
python call_llm_from_json.py url_examine/824555_com_20250110_123456_results.json
```

**참고**: 실제 파일명은 분석 시각에 따라 타임스탬프가 달라집니다. `url_examine` 폴더에서 가장 최근 파일을 확인하세요.

PowerShell에서 가장 최근 파일을 자동으로 찾는 방법:

```powershell
python call_llm_from_json.py (Get-ChildItem url_examine\*.json | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

### 5. 출력 결과

- 콘솔에 각 검사 단계별 결과가 출력됩니다
- `url_examine/{도메인명}_{타임스탬프}_results.json` 형식으로 파일이 저장됩니다
  - 예: `url_examine/824555_com_20250110_123456_results.json`
  - 예: `url_examine/docs_google_com_20250110_123456_results.json`
- LLM 분석 시 0-100 사이의 위험도 점수와 상세한 근거가 제공됩니다

**파일명 형식의 장점**:
- **충돌 방지**: 같은 도메인을 여러 번 분석해도 타임스탬프로 구분
- **서브도메인 구분**: `docs.google.com`과 `mail.google.com`을 별도로 저장
- **추적 용이**: 분석 시각을 파일명에서 바로 확인 가능

### 주의사항

- `--dynamic` 옵션 사용 시 `chromium-browser`와 `chromedriver`가 설치되어 있어야 합니다
- 타이포스쿼팅 검사를 위해서는 `data/tranco_2NW29.csv` 파일이 필요합니다
- 모든 분석 대상 URL은 잠재적으로 위험할 수 있으므로 주의하세요
