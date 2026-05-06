"""
Parse SCCS Opinion and CIR Safety Report PDFs into structured JSON.
Extracts: ingredient name, CAS number, NOAEL, max concentration,
product type restrictions, safety conclusion, date.

Usage:
  python parse-safety-opinions.py <pdf_path_or_directory> [--source sccs|cir] [--output results.json]
"""

import fitz  # PyMuPDF
import re
import json
import sys
import os
from pathlib import Path


def extract_text(pdf_path: str) -> str:
    """Extract full text from a PDF file."""
    doc = fitz.open(pdf_path)
    text = ""
    for page in doc:
        text += page.get_text()
    doc.close()
    return text


def extract_cas_numbers(text: str) -> list[str]:
    """Extract CAS numbers from text (format: digits-digits-digit)."""
    pattern = r'\b(\d{2,7}-\d{2}-\d)\b'
    matches = re.findall(pattern, text)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return unique


def extract_noael_values(text: str) -> list[dict]:
    """Extract NOAEL values with route and units."""
    results = []
    # Pattern: NOAEL followed by value and units
    patterns = [
        r'NOAEL\s*(?:of|=|:|\s)\s*(\d+[\.,]?\d*)\s*(mg/kg\s*(?:bw|body\s*weight)?(?:/day|/d)?)',
        r'NOAEL\s*(?:was|is)\s*(?:determined\s*(?:to\s*be|as)\s*)?(\d+[\.,]?\d*)\s*(mg/kg\s*(?:bw|body\s*weight)?(?:/day|/d)?)',
        r'no[- ]observed[- ]adverse[- ]effect[- ]level\s*(?:\(NOAEL\))?\s*(?:of|=|:|\s)\s*(\d+[\.,]?\d*)\s*(mg/kg\s*(?:bw|body\s*weight)?(?:/day|/d)?)',
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(1).replace(',', '.')
            unit = match.group(2).strip()

            # Try to find route nearby (within 200 chars before/after)
            start = max(0, match.start() - 200)
            end = min(len(text), match.end() + 200)
            context = text[start:end].lower()

            route = "not specified"
            if "oral" in context or "gavage" in context:
                route = "oral"
            elif "dermal" in context:
                route = "dermal"
            elif "inhalation" in context:
                route = "inhalation"
            elif "subcutaneous" in context:
                route = "subcutaneous"

            results.append({
                "value": float(value),
                "unit": unit,
                "route": route,
            })

    # Deduplicate by value+route
    seen = set()
    unique = []
    for r in results:
        key = f"{r['value']}_{r['route']}"
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique


def extract_max_concentration(text: str) -> list[dict]:
    """Extract maximum safe concentration values."""
    results = []
    patterns = [
        r'maximum\s+concentration\s+of\s+(\d+[\.,]?\d*)\s*%',
        r'safe\s+(?:for\s+use\s+)?(?:in\s+\w+\s+)?(?:at|up\s+to)\s+(?:a\s+)?(?:maximum\s+)?(?:concentration\s+of\s+)?(\d+[\.,]?\d*)\s*%',
        r'up\s+to\s+(\d+[\.,]?\d*)\s*%\s+(?:in\s+)',
        r'(\d+[\.,]?\d*)\s*%\s+(?:in\s+(?:leave-on|rinse-off|cosmetic))',
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(1).replace(',', '.')

            # Try to find product type nearby
            start = max(0, match.start() - 100)
            end = min(len(text), match.end() + 150)
            context = text[start:end].lower()

            product_type = "general"
            if "leave-on" in context:
                product_type = "leave-on"
            elif "rinse-off" in context:
                product_type = "rinse-off"
            elif "oral" in context or "toothpaste" in context or "mouthwash" in context:
                product_type = "oral care"
            elif "hair dye" in context or "hair colour" in context:
                product_type = "hair dye"
            elif "spray" in context or "aerosol" in context:
                product_type = "spray/aerosol"
            elif "nail" in context:
                product_type = "nail product"
            elif "eye" in context:
                product_type = "eye area"

            results.append({
                "max_percent": float(value),
                "product_type": product_type,
            })

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        key = f"{r['max_percent']}_{r['product_type']}"
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique


def extract_safety_conclusion(text: str) -> dict:
    """Extract overall safety conclusion."""
    text_lower = text.lower()

    # SCCS style conclusions
    sccs_patterns = [
        (r'the\s+sccs\s+considers\s+.*?(safe|not\s+safe|unsafe|insufficient\s+data)', "sccs"),
        (r'the\s+sccs\s+is\s+of\s+the\s+opinion\s+that\s+.*?(safe|not\s+safe|unsafe)', "sccs"),
        (r'conclusion.*?(?:is|are)\s+(safe|not\s+safe|unsafe)', "sccs"),
    ]

    # CIR style conclusions
    cir_patterns = [
        (r'the\s+(?:expert\s+)?panel\s+concluded\s+that\s+.*?(safe|not\s+safe|unsafe|insufficient)', "cir"),
        (r'(?:is|are)\s+safe\s+(?:in|for)\s+(?:use\s+in\s+)?cosmetics?\s+(?:in\s+the\s+present\s+practices)', "cir"),
    ]

    for pattern, source in sccs_patterns + cir_patterns:
        match = re.search(pattern, text_lower)
        if match:
            # Get surrounding context for full conclusion text
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 200)
            conclusion_text = text[start:end].strip()
            # Clean up
            conclusion_text = re.sub(r'\s+', ' ', conclusion_text)

            verdict = "safe"
            full_match = match.group(0)
            if "not safe" in full_match or "unsafe" in full_match:
                verdict = "not safe"
            elif "insufficient" in full_match:
                verdict = "insufficient data"

            return {
                "verdict": verdict,
                "conclusion_text": conclusion_text[:500],
                "source_type": source,
            }

    return {
        "verdict": "unknown",
        "conclusion_text": "",
        "source_type": "unknown",
    }


def extract_ingredient_name(text: str, filename: str) -> str:
    """Extract ingredient name from text or filename."""
    # Try from SCCS-style title
    match = re.search(r'(?:opinion|assessment)\s+(?:on|of)\s+(.+?)(?:\n|\(|CAS)', text[:2000], re.IGNORECASE)
    if match:
        name = match.group(1).strip()
        name = re.sub(r'\s+', ' ', name)
        if len(name) < 200:
            return name

    # Try from CIR-style title
    match = re.search(r'Safety\s+Assessment\s+of\s+(.+?)(?:\n|as\s+Used)', text[:2000], re.IGNORECASE)
    if match:
        name = match.group(1).strip()
        name = re.sub(r'\s+', ' ', name)
        if len(name) < 200:
            return name

    # Fall back to filename
    name = Path(filename).stem
    name = re.sub(r'sccs_o_\d+|sccs_s_\d+', '', name, flags=re.IGNORECASE)
    name = name.replace('_', ' ').replace('-', ' ').strip()
    return name if name else "Unknown"


def extract_date(text: str) -> str:
    """Extract adoption/publication date."""
    patterns = [
        r'adopted\s+(?:on\s+)?(\d{1,2}\s+\w+\s+\d{4})',
        r'(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4})',
        r'(\w+\s+\d{1,2},?\s+\d{4})',
    ]
    for pattern in patterns:
        match = re.search(pattern, text[:3000], re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return "unknown"


def extract_sccs_reference(text: str) -> str:
    """Extract SCCS reference code."""
    match = re.search(r'(SCCS/\d+/\d+)', text[:2000])
    if match:
        return match.group(1)
    return ""


def parse_pdf(pdf_path: str, source: str = "auto") -> dict:
    """Parse a single PDF and return structured data."""
    text = extract_text(pdf_path)
    filename = os.path.basename(pdf_path)

    # Auto-detect source
    if source == "auto":
        if "SCCS" in text[:5000] or "sccs" in filename.lower():
            source = "sccs"
        elif "CIR" in text[:5000] or "Cosmetic Ingredient Review" in text[:5000]:
            source = "cir"
        else:
            source = "unknown"

    result = {
        "file": filename,
        "source": source,
        "ingredient_name": extract_ingredient_name(text, filename),
        "cas_numbers": extract_cas_numbers(text[:5000]),  # CAS usually in first few pages
        "noael_values": extract_noael_values(text),
        "max_concentrations": extract_max_concentration(text),
        "safety_conclusion": extract_safety_conclusion(text),
        "date": extract_date(text),
    }

    if source == "sccs":
        result["sccs_reference"] = extract_sccs_reference(text)

    return result


def process_directory(dir_path: str, source: str = "auto", limit: int = 0) -> list[dict]:
    """Process all PDFs in a directory."""
    results = []
    pdf_files = sorted(Path(dir_path).glob("**/*.pdf"))

    if limit > 0:
        pdf_files = pdf_files[:limit]

    total = len(pdf_files)
    for i, pdf_path in enumerate(pdf_files):
        try:
            print(f"[{i+1}/{total}] Parsing {pdf_path.name}...")
            result = parse_pdf(str(pdf_path), source)
            results.append(result)
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({
                "file": pdf_path.name,
                "error": str(e),
            })

    return results


def generate_sql(results: list[dict], table: str = "safety_opinions") -> str:
    """Generate SQL INSERT statements for the parsed results."""
    sql_lines = [f"""CREATE TABLE IF NOT EXISTS {table} (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  ingredient_name TEXT,
  cas_number TEXT,
  sccs_reference TEXT,
  noael_value REAL,
  noael_unit TEXT,
  noael_route TEXT,
  max_concentration_percent REAL,
  product_type TEXT,
  safety_verdict TEXT,
  conclusion_text TEXT,
  opinion_date TEXT,
  file_name TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_so_cas ON {table}(cas_number);
CREATE INDEX IF NOT EXISTS idx_so_ingredient ON {table}(ingredient_name);
CREATE INDEX IF NOT EXISTS idx_so_source ON {table}(source);
"""]

    for r in results:
        if "error" in r:
            continue

        cas = r["cas_numbers"][0] if r["cas_numbers"] else None

        # Create one row per NOAEL value (or one row if no NOAEL)
        noael_list = r["noael_values"] if r["noael_values"] else [{"value": None, "unit": None, "route": None}]
        max_conc_list = r["max_concentrations"] if r["max_concentrations"] else [{"max_percent": None, "product_type": None}]

        for noael in noael_list:
            for mc in max_conc_list:
                name = r["ingredient_name"].replace("'", "''")
                conclusion = r["safety_conclusion"]["conclusion_text"].replace("'", "''") if r["safety_conclusion"]["conclusion_text"] else ""
                verdict = r["safety_conclusion"]["verdict"]
                ref = r.get("sccs_reference", "")
                fname = r["file"].replace("'", "''")

                noael_val = noael["value"] if noael["value"] else "NULL"
                noael_unit = f"'{noael['unit']}'" if noael.get("unit") else "NULL"
                noael_route = f"'{noael['route']}'" if noael.get("route") else "NULL"
                max_pct = mc["max_percent"] if mc.get("max_percent") else "NULL"
                prod_type = f"'{mc['product_type']}'" if mc.get("product_type") else "NULL"

                cas_sql = f"'{cas}'" if cas else "NULL"
                ref_sql = f"'{ref}'" if ref else "NULL"

                sql_lines.append(
                    f"INSERT INTO {table} (source, ingredient_name, cas_number, sccs_reference, "
                    f"noael_value, noael_unit, noael_route, max_concentration_percent, product_type, "
                    f"safety_verdict, conclusion_text, opinion_date, file_name) VALUES ("
                    f"'{r['source']}', '{name}', {cas_sql}, "
                    f"{ref_sql}, "
                    f"{noael_val}, {noael_unit}, {noael_route}, "
                    f"{max_pct}, {prod_type}, "
                    f"'{verdict}', '{conclusion[:500]}', '{r['date']}', '{fname}');"
                )

    return "\n".join(sql_lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse-safety-opinions.py <pdf_or_directory> [--source sccs|cir] [--output file.json] [--sql file.sql] [--limit N]")
        sys.exit(1)

    target = sys.argv[1]
    source = "auto"
    output = None
    sql_output = None
    limit = 0

    # Parse args
    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == "--source" and i + 1 < len(sys.argv):
            source = sys.argv[i + 1]
        elif arg == "--output" and i + 1 < len(sys.argv):
            output = sys.argv[i + 1]
        elif arg == "--sql" and i + 1 < len(sys.argv):
            sql_output = sys.argv[i + 1]
        elif arg == "--limit" and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])

    if os.path.isdir(target):
        results = process_directory(target, source, limit)
    else:
        results = [parse_pdf(target, source)]

    # Stats
    total = len(results)
    errors = sum(1 for r in results if "error" in r)
    with_noael = sum(1 for r in results if "error" not in r and r.get("noael_values"))
    with_cas = sum(1 for r in results if "error" not in r and r.get("cas_numbers"))
    with_conc = sum(1 for r in results if "error" not in r and r.get("max_concentrations"))

    print(f"\n--- RESULTS ---")
    print(f"Total PDFs: {total}")
    print(f"Errors: {errors}")
    print(f"With NOAEL: {with_noael}")
    print(f"With CAS: {with_cas}")
    print(f"With max concentration: {with_conc}")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"JSON saved to {output}")

    if sql_output:
        sql = generate_sql(results)
        with open(sql_output, "w", encoding="utf-8") as f:
            f.write(sql)
        print(f"SQL saved to {sql_output}")

    if not output and not sql_output:
        print(json.dumps(results, indent=2, ensure_ascii=False))
