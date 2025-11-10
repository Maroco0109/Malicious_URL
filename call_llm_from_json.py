import os
import json
import sys
import openai
from dotenv import load_dotenv
from pathlib import Path

# Security 모듈 임포트
from utils.security import (
    validate_openai_api_key,
    sanitize_error_message,
    PathTraversalError
)

def main():
    load_dotenv()
    if len(sys.argv) != 2:
        print("사용법: python call_llm_from_json.py <result.json 경로>")
        sys.exit(1)

    json_path = sys.argv[1]

    # 경로 보안 검증
    try:
        # 절대 경로로 변환하여 검증
        json_path_obj = Path(json_path).resolve()

        # 파일이 존재하는지 확인
        if not json_path_obj.exists():
            print(f"[!] 파일을 찾을 수 없습니다: {json_path}")
            sys.exit(1)

        # 파일이 실제 파일인지 확인 (디렉토리가 아닌)
        if not json_path_obj.is_file():
            print(f"[!] 지정된 경로가 파일이 아닙니다: {json_path}")
            sys.exit(1)

        # JSON 파일 확장자 확인
        if json_path_obj.suffix.lower() != '.json':
            print("[!] JSON 파일만 처리할 수 있습니다 (.json 확장자 필요)")
            sys.exit(1)

    except Exception as e:
        print(f"[!] 경로 검증 중 오류: {sanitize_error_message(e)}")
        sys.exit(1)

    # 1) 환경 변수에서 API 키 로드
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("[!] 환경 변수 OPENAI_API_KEY가 설정되어 있지 않습니다.")
        sys.exit(1)

    # API 키 형식 검증
    try:
        validate_openai_api_key(api_key)
    except ValueError as e:
        print(f"[!] {e}")
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
    try:
        # 입력 파일의 디렉토리와 파일명 추출
        input_dir = json_path_obj.parent
        base_name = json_path_obj.stem  # 확장자 제외한 파일명
        output_filename = f"{base_name}_llm_result.json"

        # 출력 경로 생성
        output_path = input_dir / output_filename

        # 파일 저장
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        print(f"\n[*] LLM 결과가 JSON으로 저장되었습니다: {output_path}")

    except Exception as e:
        print(f"\n[!] JSON 저장 중 오류: {sanitize_error_message(e)}")


if __name__ == "__main__":
    main()
