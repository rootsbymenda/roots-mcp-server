"""
Scrape CIR Reports from cir-reports.cir-safety.org
Step 1: Get all ingredient page links
Step 2: Get PDF links from each ingredient page
Step 3: Download PDFs

Usage:
  python scrape-cir.py --step links    # Get ingredient links
  python scrape-cir.py --step pdfs     # Get PDF URLs from ingredient pages
  python scrape-cir.py --step download # Download all PDFs
  python scrape-cir.py --step all      # Run everything
"""

import requests
from bs4 import BeautifulSoup
import json
import os
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "https://cir-reports.cir-safety.org"
CACHE_DIR = Path("C:/BENDA_PROJECT/cir-reports/cache")
PDF_DIR = Path("C:/BENDA_PROJECT/cir-reports/pdfs")

CACHE_DIR.mkdir(parents=True, exist_ok=True)
PDF_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


def get_ingredient_links():
    """Step 1: Get all ingredient page links from the main page."""
    print("Step 1: Getting ingredient page links...")
    resp = requests.get(BASE_URL, headers=HEADERS, timeout=30)
    soup = BeautifulSoup(resp.text, "html.parser")

    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "cir-ingredient-status-report" in href:
            if href.startswith("/"):
                href = BASE_URL + href
            links.add(href)

    # Also check for alphabetical index pages
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith(BASE_URL) or href.startswith("/"):
            full_url = href if href.startswith("http") else BASE_URL + href
            if full_url != BASE_URL and "cir-ingredient-status-report" not in full_url:
                # Could be a letter page (A, B, C...)
                try:
                    print(f"  Checking sub-page: {full_url}")
                    sub_resp = requests.get(full_url, headers=HEADERS, timeout=15)
                    sub_soup = BeautifulSoup(sub_resp.text, "html.parser")
                    for sub_a in sub_soup.find_all("a", href=True):
                        sub_href = sub_a["href"]
                        if "cir-ingredient-status-report" in sub_href:
                            if sub_href.startswith("/"):
                                sub_href = BASE_URL + sub_href
                            links.add(sub_href)
                    time.sleep(0.5)
                except Exception as e:
                    print(f"  Error on {full_url}: {e}")

    links_list = sorted(links)
    outpath = CACHE_DIR / "ingredient_page_links.json"
    with open(outpath, "w") as f:
        json.dump(links_list, f, indent=2)

    print(f"Found {len(links_list)} ingredient page links")
    return links_list


def get_pdf_links(ingredient_links=None):
    """Step 2: Visit each ingredient page and collect PDF links."""
    if ingredient_links is None:
        inpath = CACHE_DIR / "ingredient_page_links.json"
        with open(inpath) as f:
            ingredient_links = json.load(f)

    print(f"Step 2: Getting PDF links from {len(ingredient_links)} ingredient pages...")
    all_pdfs = []

    for i, link in enumerate(ingredient_links):
        try:
            if (i + 1) % 50 == 0:
                print(f"  [{i+1}/{len(ingredient_links)}] ...")

            resp = requests.get(link, headers=HEADERS, timeout=15)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Get ingredient name from page title or heading
            title = soup.find("h1") or soup.find("h2")
            name = title.get_text(strip=True) if title else "Unknown"

            # Find PDF links
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.lower().endswith(".pdf"):
                    if href.startswith("/"):
                        href = BASE_URL + href
                    elif not href.startswith("http"):
                        href = BASE_URL + "/" + href

                    all_pdfs.append({
                        "ingredient_name": name,
                        "pdf_url": href,
                        "link_text": a.get_text(strip=True),
                        "ingredient_page": link,
                    })

            time.sleep(0.3)  # Be nice to the server
        except Exception as e:
            print(f"  Error on {link}: {e}")

    outpath = CACHE_DIR / "all_pdf_links.json"
    with open(outpath, "w") as f:
        json.dump(all_pdfs, f, indent=2)

    print(f"Found {len(all_pdfs)} PDF links")
    return all_pdfs


def download_pdf(pdf_info: dict) -> dict:
    """Download a single PDF."""
    url = pdf_info["pdf_url"]
    filename = url.split("/")[-1]
    filepath = PDF_DIR / filename

    if filepath.exists():
        return {"file": filename, "status": "exists"}

    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 200 and len(resp.content) > 100:
            with open(filepath, "wb") as f:
                f.write(resp.content)
            return {"file": filename, "status": "downloaded", "size": len(resp.content)}
        else:
            return {"file": filename, "status": f"error_{resp.status_code}"}
    except Exception as e:
        return {"file": filename, "status": f"error: {e}"}


def download_all_pdfs(pdf_links=None, max_workers=5):
    """Step 3: Download all PDFs."""
    if pdf_links is None:
        inpath = CACHE_DIR / "all_pdf_links.json"
        with open(inpath) as f:
            pdf_links = json.load(f)

    print(f"Step 3: Downloading {len(pdf_links)} PDFs...")
    results = {"downloaded": 0, "exists": 0, "errors": 0}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(download_pdf, pdf): pdf for pdf in pdf_links}
        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            if result["status"] == "downloaded":
                results["downloaded"] += 1
            elif result["status"] == "exists":
                results["exists"] += 1
            else:
                results["errors"] += 1

            if (i + 1) % 100 == 0:
                print(f"  [{i+1}/{len(pdf_links)}] Downloaded: {results['downloaded']}, "
                      f"Exists: {results['exists']}, Errors: {results['errors']}")

    print(f"\nDone! Downloaded: {results['downloaded']}, "
          f"Already existed: {results['exists']}, Errors: {results['errors']}")
    return results


if __name__ == "__main__":
    step = "all"
    if "--step" in sys.argv:
        idx = sys.argv.index("--step")
        step = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "all"

    if step in ("links", "all"):
        links = get_ingredient_links()

    if step in ("pdfs", "all"):
        pdfs = get_pdf_links()

    if step in ("download", "all"):
        download_all_pdfs()
