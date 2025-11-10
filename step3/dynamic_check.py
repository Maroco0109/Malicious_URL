# step3/dynamic_check.py

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from urllib.parse import urlparse
import time
import sys
from shutil import which

# Security 모듈 임포트
from utils.security import (
    validate_url,
    sanitize_error_message,
    clamp_value,
    SSRFError
)


def check_dynamic_threat(url: str, wait_time: float = 5.0, allow_private_ips: bool = False, disable_sandbox: bool = False) -> dict:
    """
    Selenium(헤드리스 Chromium)을 사용해 실제 페이지를 렌더링하고,
    로드 과정에서 발생하는 동적 행위를 관찰합니다.

    ⚠️  보안 경고:
    - 이 함수는 악성 웹사이트를 분석할 때 위험할 수 있습니다
    - 격리된 환경(VM, Docker)에서만 실행하세요
    - disable_sandbox=True는 매우 위험하며 테스트 목적으로만 사용하세요

    Args:
        url: 분석할 URL
        wait_time: 페이지 로드 후 대기 시간 (초)
        allow_private_ips: 내부 IP 접근 허용 여부
        disable_sandbox: 샌드박스 비활성화 (⚠️ 위험)
    """
    result = {
        "url": url,
        "page_loaded": False,
        "final_url": None,
        "redirect_chain": [],
        "download_attempt": False,
        "download_links": [],
        "popup_attempt": False,
        "popup_titles": [],
        "external_domains_contacted": [],
        "comment": "",
        "security_warnings": []
    }

    # SSRF 방지 - URL 검증
    try:
        validate_url(url, allow_private_ips=allow_private_ips)
    except SSRFError as e:
        result["comment"] = f"SSRF 차단: {e}"
        return result

    # Wait time 제한 (1-30초)
    wait_time = clamp_value(wait_time, 1.0, 30.0)

    # ⚠️ 샌드박스 비활성화 경고
    if disable_sandbox:
        warning = "⚠️  위험: 브라우저 샌드박스가 비활성화되었습니다. 격리된 환경에서만 실행하세요!"
        result["security_warnings"].append(warning)
        print(f"\n{warning}\n", file=sys.stderr)

    # ── 헤드리스 옵션 설정 ──
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")

    # Sandbox 설정
    if disable_sandbox:
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--no-zygote")
    else:
        # 샌드박스를 활성화하지만, 일부 환경에서 권한 문제가 발생할 수 있음
        pass

    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--remote-debugging-port=9222")
    chrome_options.add_argument("--no-first-run")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])

    # 추가 보안 옵션
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-plugins")
    chrome_options.add_argument("--disable-notifications")
    chrome_options.add_argument("--disable-geolocation")

    # ── Chromium 바이너리 경로 지정 ──
    chromium_path = which("chromium-browser")
    if not chromium_path:
        result["comment"] = (
            "Chromium 브라우저를 찾을 수 없습니다. "
            "APT로 설치된 chromium-browser가 있어야 합니다."
        )
        return result
    chrome_options.binary_location = chromium_path

    # ── 시스템에 설치된 ChromeDriver 경로 지정 ──
    chromedriver_path = which("chromedriver")
    if not chromedriver_path:
        result["comment"] = (
            "Chromedriver를 찾을 수 없습니다. "
            "`sudo apt install chromium-chromedriver`를 통해 설치해주세요."
        )
        return result

    driver = None
    try:
        driver = webdriver.Chrome(
            service=ChromeService(chromedriver_path),
            options=chrome_options
        )
        driver.set_page_load_timeout(20)
        driver.get(url)
        result["page_loaded"] = True

        # 1) 리다이렉트 관찰
        final = driver.current_url
        result["final_url"] = final
        if final != url:
            result["redirect_chain"].append(final)

        # 2) 새 창/팝업 체크
        time.sleep(wait_time)
        handles = driver.window_handles
        if len(handles) > 1:
            result["popup_attempt"] = True
            for h in handles[1:]:
                driver.switch_to.window(h)
                result["popup_titles"].append(driver.title)
            driver.switch_to.window(handles[0])

        # 3) <a download> 태그로 다운로드 시도 감지
        download_links = driver.find_elements("xpath", "//a[@download]")
        if download_links:
            result["download_attempt"] = True
            for a in download_links:
                href = a.get_attribute("href")
                result["download_links"].append(href)

        # 4) 외부 도메인 호출 감시 (스크립트/src, img/src, link/href)
        orig_domain = urlparse(url).hostname
        tags_with_src = driver.find_elements("xpath", "//script[@src] | //img[@src] | //link[@href]")
        for elem in tags_with_src:
            src_attr = elem.get_attribute("src") or elem.get_attribute("href")
            if not src_attr:
                continue
            host = urlparse(src_attr).hostname
            if host and host != orig_domain:
                result["external_domains_contacted"].append(host)

    except Exception as e:
        result["comment"] = f"동적 분석 중 오류 발생: {sanitize_error_message(e)}"
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass  # 드라이버 종료 실패는 무시

    # 5) comment 구성
    if not result["comment"]:
        comments = []
        if result["redirect_chain"]:
            comments.append(f"자동 리다이렉트 → 최종 URL: {result['final_url']}")
        if result["popup_attempt"]:
            comments.append(f"팝업 시도: {result['popup_titles']}")
        if result["download_attempt"]:
            comments.append(f"다운로드 시도 링크: {result['download_links']}")
        if result["external_domains_contacted"]:
            exd = set(result["external_domains_contacted"])
            comments.append(f"외부 도메인 호출: {', '.join(exd)}")

        if not comments:
            result["comment"] = "동적 분석 단계에서 이상 행위(리다이렉트, 팝업, 다운로드, 외부 호출) 없음"
        else:
            result["comment"] = "; ".join(comments)

    return result
