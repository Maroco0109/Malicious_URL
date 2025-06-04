import csv

def load_whitelist_from_tranco(csv_path: str, top_n: int = 1000000) -> list[str]:
    """
    tranco.csv 에서 도메인 컬럼만 추출하여 리스트로 반환.
    top_n을 지정하면 상위 top_n개 도메인만 로드합니다.
    """
    domains = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # 헤더 스킵 (rank,domain)
        for i, row in enumerate(reader, start=1):
            if i > top_n:
                break
            # row = [rank, domain], domain만 append
            domains.append(row[1].strip().lower())
    return domains

def load_whitelist_from_txt(txt_path: str, max_lines: int | None = None) -> list[str]:
    """
    도메인만 한 줄씩 적힌 텍스트 파일을 로드하여 리스트로 반환.
    max_lines=None 이면 모든 줄을, 아니면 지정한 만큼만 읽습니다.
    """
    domains = []
    with open(txt_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            if max_lines and i > max_lines:
                break
            dom = line.strip().lower()
            if dom and not dom.startswith("#"):
                domains.append(dom)
    return domains