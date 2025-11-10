import os
import json
import sys
import openai
from dotenv import load_dotenv

def main():
    load_dotenv()
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
            model="gpt-3.5-turbo",
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
    content = response.choices[0].message.content
    print(content)

    # 6) JSON 파일로 저장
    output_data = {
        "url": features.get("url", "unknown"),
        "llm_model": "gpt-3.5-turbo",
        "llm_response": content,
        "original_features": features
    }

    # 출력 파일명 생성 (입력 파일과 같은 디렉토리에 저장)
    dir_name = os.path.dirname(json_path)
    base_name = os.path.basename(json_path).rsplit('.', 1)[0]
    output_filename = f"{base_name}_llm_result.json"

    # 디렉토리가 있으면 그 안에 저장, 없으면 현재 디렉토리에 저장
    if dir_name:
        output_path = os.path.join(dir_name, output_filename)
    else:
        output_path = output_filename

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        print(f"\n[*] LLM 결과가 JSON으로 저장되었습니다: {output_path}")
    except Exception as e:
        print(f"\n[!] JSON 저장 중 오류: {e}")


if __name__ == "__main__":
    main()
