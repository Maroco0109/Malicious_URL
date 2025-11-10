# main.py

import argparse
import json
import os
from urllib.parse import urlparse

# Step1 모듈 임포트
from step1.idn_check import check_idn
from step1.typosquat_check import check_typosquat
from step1.ssl_check import get_certificate_info
from step1.scheme_check import check_scheme_and_port
from utils.load_whitelist import load_whitelist_from_tranco, load_whitelist_from_txt

# Step2 모듈 임포트
from step2.whois_check import get_whois_info
from step2.dns_check import query_dns_records
from step2.urlinfo_check import parse_url_info

# Step3 모듈 임포트
from step3.static_check import check_static_threat
from step3.dynamic_check import check_dynamic_threat

# Security 모듈 임포트
from utils.security import validate_safe_path, sanitize_filename, PathTraversalError


def extract_domain_for_filename(url):
    """
    URL에서 파일명으로 사용할 도메인 부분을 추출합니다.
    전체 호스트명을 사용하여 충돌을 방지하고, 타임스탬프를 추가합니다.

    예:
        http://www.824555.com/path -> 824555_com_20250110_123456
        https://docs.google.com -> docs_google_com_20250110_123456
        https://google.com -> google_com_20250110_123456
    """
    from datetime import datetime

    parsed = urlparse(url)
    hostname = parsed.hostname or url

    # www. 제거 (선택적)
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    # 점을 언더스코어로 변경 (파일명 안전성)
    safe_hostname = hostname.replace('.', '_')

    # 타임스탬프 추가 (같은 도메인을 여러 번 분석할 때 충돌 방지)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 최종 파일명: {도메인}_{타임스탬프}
    filename_base = f"{safe_hostname}_{timestamp}"

    return filename_base


def parse_args():
    parser = argparse.ArgumentParser(
        description="Step1~Step3 통합 도구 (결과를 JSON으로 저장 가능)"
    )
    parser.add_argument("--url", "-u", required=True, help="검사할 대상 URL (예: https://example.com)")
    parser.add_argument("--domain", "-d", help="WHOIS/DNS용 도메인 지정 (예: example.com)")

    # Step1 옵션
    parser.add_argument("--idn", action="store_true", help="IDN 검사")
    parser.add_argument("--typo", action="store_true", help="타이포스쿼팅 검사")
    parser.add_argument("--typo-dataset", choices=["tranco"], help="타이포스쿼팅용 데이터셋 종류 (현재: tranco)")
    parser.add_argument("--typo-path", help="타이포스쿼팅용 도메인 리스트 파일 경로 (CSV 또는 TXT)")
    parser.add_argument("--ssl", action="store_true", help="SSL/TLS 인증서 검사")
    parser.add_argument("--scheme", action="store_true", help="스킴/포트 검사")

    # Step2 옵션
    parser.add_argument("--whois", action="store_true", help="WHOIS 조회 실행")
    parser.add_argument("--dns", action="store_true", help="DNS 레코드 조회 실행")
    parser.add_argument("--urlinfo", action="store_true", help="URL 구조 분석 실행")

    # Step3 옵션
    parser.add_argument("--static", action="store_true", help="정적 HTML/JS 분석 실행")
    parser.add_argument("--dynamic", action="store_true", help="동적(헤드리스 브라우저) 분석 실행")

    # 결과를 JSON으로 저장할 경로
    parser.add_argument("--export-json", action="store_true", help="모든 단계 결과를 JSON 파일로 저장 (도메인 기반 자동 생성)")

    return parser.parse_args()


def main():
    args = parse_args()
    url = args.url

    # 결과를 담을 딕셔너리
    all_results = {"url": url}

    # 1) Step1: IDN 검사
    if args.idn:
        res_idn = check_idn(url)
        print("=== Step 1: IDN 검사 ===")
        for k, v in res_idn.items():
            print(f"{k}: {v}")
        print()
        all_results["idn_features"] = res_idn

    # 2) Step1: 타이포스쿼팅 검사
    if args.typo:
        print("=== Step 1: 타이포스쿼팅 검사 ===")
        parsed = urlparse(url)
        domain_only = parsed.hostname or url

        # 화이트리스트 로드 (tranco만 지원)
        whitelist = []
        if args.typo_dataset == "tranco":
            whitelist = load_whitelist_from_tranco("data/tranco_2NW29.csv", top_n=100000)
        elif args.typo_path:
            if args.typo_path.endswith(".csv"):
                whitelist = load_whitelist_from_tranco(args.typo_path, top_n=None)
            else:
                whitelist = load_whitelist_from_txt(args.typo_path, max_lines=None)
        else:
            print("타이포스쿼팅 검사를 위해 --typo-dataset 또는 --typo-path를 지정해주세요.")
            return

        res_typo = check_typosquat(domain_only, whitelist)
        for k, v in res_typo.items():
            print(f"{k}: {v}")
        print()
        all_results["typosquat_features"] = res_typo

    # 3) Step1: SSL 인증서 검사
    if args.ssl:
        print("=== Step 1: SSL 인증서 검사 ===")
        res_ssl = get_certificate_info(url)
        for k, v in res_ssl.items():
            print(f"{k}: {v}")
        print()
        all_results["ssl_features"] = res_ssl

    # 4) Step1: 스킴/포트 검사
    if args.scheme:
        print("=== Step 1: 스킴/포트 검사 ===")
        res_scheme = check_scheme_and_port(url)
        for k, v in res_scheme.items():
            print(f"{k}: {v}")
        print()
        all_results["scheme_features"] = res_scheme

    # 5) Step2: WHOIS/DNS/URL 정보 수집
    parsed_main = urlparse(url)
    domain_for_step2 = args.domain or parsed_main.hostname

    if args.whois:
        print("=== Step 2: WHOIS 조회 ===")
        if not domain_for_step2:
            print("WHOIS 조회를 위한 도메인을 인식할 수 없습니다.")
            res_whois = {"error": "no domain"}
        else:
            res_whois = get_whois_info(domain_for_step2)
            for k, v in res_whois.items():
                print(f"{k}: {v}")
        print()
        all_results["whois_features"] = res_whois

    if args.dns:
        print("=== Step 2: DNS 레코드 조회 ===")
        if not domain_for_step2:
            print("DNS 조회를 위한 도메인을 인식할 수 없습니다.")
            res_dns = {"error": "no domain"}
        else:
            res_dns = query_dns_records(domain_for_step2)
            for rtype, entries in res_dns.items():
                print(f"{rtype}:")
                if isinstance(entries, list):
                    for entry in entries:
                        print(f"  - value: {entry.get('value')}, ttl: {entry.get('ttl')}")
                else:
                    print(f"  - {entries}")
        print()
        all_results["dns_features"] = res_dns

    if args.urlinfo:
        print("=== Step 2: URL 구조 분석 ===")
        res_urlinfo = parse_url_info(url)
        for k, v in res_urlinfo.items():
            print(f"{k}: {v}")
        print()
        all_results["url_structure_features"] = res_urlinfo

    # 6) Step3: 정적/동적 분석
    if args.static:
        print("=== Step 3: 정적 HTML/JS 분석 ===")
        res_static = check_static_threat(url)
        for k, v in res_static.items():
            print(f"{k}: {v}")
        print()
        all_results["static_html_features"] = res_static

    if args.dynamic:
        print("=== Step 3: 동적(헤드리스 브라우저) 분석 ===")
        res_dynamic = check_dynamic_threat(url)
        for k, v in res_dynamic.items():
            print(f"{k}: {v}")
        print()
        all_results["dynamic_js_features"] = res_dynamic

    # 7) --export-json 옵션이 있으면 JSON으로 저장
    if args.export_json:
        try:
            # URL에서 도메인 추출하여 파일명 생성
            domain_name = extract_domain_for_filename(url)
            filename = f"{domain_name}_results.json"

            # 파일명 보안 검증
            filename = sanitize_filename(filename)

            # base_dir와 파일명을 결합한 전체 경로 생성
            full_path = os.path.join("url_examine", filename)

            # 경로 검증 (path traversal 방지)
            output_path = validate_safe_path(full_path, base_dir="url_examine")

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(all_results, f, ensure_ascii=False, indent=2)
            print(f"[*] 모든 결과를 JSON으로 저장했습니다: {output_path}")
        except PathTraversalError as e:
            print(f"[!] 보안 오류: {e}")
            print("[!] 파일은 url_examine 디렉토리 내에만 저장할 수 있습니다.")
        except Exception as e:
            print(f"[!] JSON 저장 중 오류 발생: {e}")


if __name__ == "__main__":
    main()
