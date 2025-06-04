import os
import json
import sys
import openai

def main():
    if len(sys.argv) != 2:
        print("사용법: python call_llm_from_json.py <result.json 경로>")
        sys.exit(1)

    json_path = sys.argv[1]

    # 1) 환경 변수에서 API 키 로드
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("[!] 환경 변수 OPENAI_API_KEY가 설정되어 있지 않습니다.")
        sys.exit(1)
    openai.api_key = api_key

    # 2) JSON 파일 로드
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            features = json.load(f)
    except Exception as e:
        print(f"[!] JSON 파일 로드 중 오류: {e}")
        sys.exit(1)

    # 3) LLM 프롬프트 생성
    prompt = f"""
아래는 특정 URL에 대한 1~3단계 종합 분석 결과입니다.
모든 필드는 신뢰도 평가와 악성 여부 판단에 필요한 중요 정보를 담고 있습니다.

{json.dumps(features, ensure_ascii=False, indent=2)}

위 JSON 정보를 바탕으로, 해당 URL이 피싱/악성코드 유포 사이트일 가능성을 0부터 100 사이 점수로 평가하고, 
왜 그 점수를 주었는지 구체적인 근거를 설명해 주세요.
"""

    # 4) OpenAI Chat Completions 호출 (openai>=1.0.0 방식)
    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo-16k",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user",   "content": prompt}
            ],
            temperature=0.0,
            max_tokens=300
        )
    except Exception as e:
        print(f"[!] LLM 호출 중 오류 발생: {e}")
        sys.exit(1)

    # 5) 결과 출력
    content = response.choices[0].message["content"]
    print(content)


if __name__ == "__main__":
    main()
