"""
Parse SCCS Opinion and CIR Safety Report PDFs into structured JSON.
Extracts: ingredient name, CAS number, NOAEL/NOEL/LOAEL, max concentration,
product type restrictions, safety conclusion, date.

V2 improvements over V1:
- Captures NOEL in addition to NOAEL
- Captures LOAEL/LOEL values
- Supports units: mg/kg, g/kg, ppm, %, mg/m3, mg/L, mL/kg, ug/kg
- Supports >, >=, and unicode >= before numeric values
- Supports comma-separated thousands (1,000 mg/kg)
- Supports mg/kg without requiring bw/body weight suffix
- Supports "concluded/determined/reported/considered to be" phrasing
- Supports "NOAEL for <ingredient> in <species> was X" (long-span connectors)
- Supports "(NOAEL)" and "(NOEL)" with trailing parenthesis after keyword
- Filters out abbreviation-only definitions (glossary entries)
- Better route detection from surrounding context
- Captures study type metadata

Usage:
  python parse-safety-opinions-v2.py <pdf_path_or_directory> [--source sccs|cir] [--output results.json]
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
    seen = set()
    unique = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return unique


# ---------------------------------------------------------------------------
# Numeric value: handles "1,000", "50", "0.5", "2.4", "50000"
# Qualifier (>, >=, etc.) is detected separately.
# Fixed: \d+ comes first to avoid partial matching of e.g. "200" from "2000"
# ---------------------------------------------------------------------------
_NUM = r'(\d+(?:,\d{3})*(?:\.\d+)?)'

# Optional qualifier that may appear right before the number
_QUAL = r'(?:[><]=?|[≥≤])?\s*'

# ---------------------------------------------------------------------------
# Unit patterns -- ordered from most specific to least specific
# ---------------------------------------------------------------------------
_UNITS = [
    r'(g\s*(?:\w+\s+)?(?:product\s*)?/\s*kg\s*(?:bw|body\s*weight)?\s*(?:/\s*(?:day|d))?)',  # g/kg, g X/kg, g commercial product/kg
    r'(mg/kg\s*(?:bw|body\s*weight)?\s*(?:/\s*(?:day|d))?)',          # mg/kg, mg/kg/day, mg/kg bw/day
    r'(mg/m\s*[³3]?\s*(?:/\s*(?:day|d))?)',                           # mg/m3
    r'(mg/L)',                                                         # mg/L
    r'(mL/kg\s*(?:bw|body\s*weight)?\s*(?:/\s*(?:day|d))?)',          # mL/kg
    r'(\xb5g/kg\s*(?:bw|body\s*weight)?\s*(?:/\s*(?:day|d))?)',       # µg/kg
    r'(ppm)',                                                          # ppm
    r'(%\s*(?:in\s+(?:the\s+)?(?:diet|feed|food|water))?)',            # % or % in diet
]


def _is_glossary_entry(text: str, match_start: int) -> bool:
    """Check if a NOAEL/NOEL match is just a glossary/abbreviation definition."""
    start = max(0, match_start - 10)
    end = min(len(text), match_start + 250)
    ctx = text[start:end]
    # "NOAEL  no-observed-adverse-effect-level"
    if re.match(
        r'^\s*(?:NOAEL|NOEL|LOAEL|LOEL)\s*(?:=|:|\s{2,})\s*(?:no[- ]?observ|lowest[- ]?observ)',
        ctx, re.IGNORECASE
    ):
        return True
    # "NOAEL  no-observable-adverse-effect level\nOECD"
    if re.search(r'(?:NOAEL|NOEL)\s+no[- ]?observ.*?(?:level|OECD|NR\b|not reported)', ctx, re.IGNORECASE):
        return True
    # "NOAEL     no observed adverse effect level\nNOEL" (abbreviation table)
    if re.search(r'(?:NOAEL|NOEL)\s{3,}no\s', ctx, re.IGNORECASE):
        return True
    return False


def _clean_value(raw: str) -> float:
    """Convert a string number (possibly with commas) to float."""
    return float(raw.replace(',', ''))


def _detect_route(text: str, match_start: int, match_end: int) -> str:
    """Detect exposure route from context around the match."""
    start = max(0, match_start - 300)
    end = min(len(text), match_end + 200)
    ctx = text[start:end].lower()

    if "oral" in ctx or "gavage" in ctx or "diet" in ctx or "feed" in ctx or "drinking water" in ctx:
        return "oral"
    if "dermal" in ctx or "topical" in ctx or "cutaneous" in ctx or "skin" in ctx:
        return "dermal"
    if "inhalation" in ctx or "inhale" in ctx or "nose" in ctx or "nasal" in ctx or "mg/m" in ctx:
        return "inhalation"
    if "subcutaneous" in ctx or "s.c." in ctx:
        return "subcutaneous"
    if "intravaginal" in ctx or "vaginal" in ctx:
        return "intravaginal"
    if "intranasal" in ctx:
        return "intranasal"
    if "intraperitoneal" in ctx or "i.p." in ctx:
        return "intraperitoneal"
    return "not specified"


def _detect_study_type(text: str, match_start: int, match_end: int) -> str:
    """Detect study type from context around the match."""
    start = max(0, match_start - 300)
    end = min(len(text), match_end + 200)
    ctx = text[start:end].lower()

    if "reproductive" in ctx or "reproduction" in ctx:
        return "reproductive"
    if "developmental" in ctx or "teratogen" in ctx or "embryo" in ctx:
        return "developmental"
    if "chronic" in ctx or "carcinogen" in ctx or "2-year" in ctx or "2 year" in ctx:
        return "chronic"
    if "subchronic" in ctx or "90-day" in ctx or "90 day" in ctx or "13-week" in ctx or "13 week" in ctx:
        return "subchronic"
    if "subacute" in ctx or "28-day" in ctx or "28 day" in ctx or "4-week" in ctx or "4 week" in ctx:
        return "subacute"
    if "acute" in ctx:
        return "acute"
    return "not specified"


def _detect_qualifier(text: str, num_match_start: int) -> str:
    """Detect if value has a qualifier like > >= etc. by looking just before the number."""
    start = max(0, num_match_start - 30)
    prefix = text[start:num_match_start].lower()
    if ">=" in prefix or "\u2265" in prefix:
        return ">="
    if ">" in prefix:
        return ">"
    if "<=" in prefix or "\u2264" in prefix:
        return "<="
    if "<" in prefix:
        return "<"
    if "exceed" in prefix or "more than" in prefix or "greater than" in prefix:
        return ">"
    if "less than" in prefix:
        return "<"
    return ""


def extract_dose_values(text: str) -> dict:
    """
    Extract NOAEL, NOEL, LOAEL, and LOEL values with route, units, and study context.

    Strategy (V2 optimized):
      1. Find all keyword positions (NOAEL, NOEL, LOAEL, LOEL) in ONE pass.
      2. For each hit, extract a local window (keyword pos to +300 chars forward).
      3. Run a compact set of value+unit regexes ONLY on that small window.
      4. Also run a backward scan for reverse patterns ("50 mg/kg is an oral NOEL").

    This avoids running hundreds of regexes on the full (often 200KB+) text.
    """
    results = {
        "noael_values": [],
        "noel_values": [],
        "loael_values": [],
        "loel_values": [],
    }

    # -----------------------------------------------------------------------
    # Step 1: find all keyword positions in one pass
    # -----------------------------------------------------------------------
    kw_pattern = re.compile(
        r'(?:NOAELs?|(?<![A-Za-z])NOEL(?![A-Za-z])|LOAELs?|(?<![A-Za-z])LOEL(?![A-Za-z])'
        r'|no[- ]?observed[- ]?adverse[- ]?effect[- ]?level'
        r'|no[- ]?observed[- ]?effect[- ]?level'
        r'|no[- ]?adverse[- ]?effect[- ]?level'
        r'|no[- ]?effect[- ]?level'
        r'|lowest[- ]?observed[- ]?adverse[- ]?effect[- ]?level'
        r'|lowest[- ]?observed[- ]?effect[- ]?level'
        r')\)?',
        re.IGNORECASE
    )

    def _classify_keyword(kw_text: str) -> str:
        """Map keyword text to metric key."""
        kw_up = kw_text.upper().rstrip(')')
        if kw_up.startswith('NOAEL') or 'ADVERSE' in kw_up:
            if kw_up.startswith('LOAEL') or kw_up.startswith('LOWEST'):
                return "loael_values"
            return "noael_values"
        if kw_up.startswith('LOEL') or kw_up.startswith('LOWEST'):
            return "loel_values"
        if kw_up.startswith('NOEL') or 'EFFECT' in kw_up:
            return "noel_values"
        return "noael_values"

    # -----------------------------------------------------------------------
    # Step 2: combined value+unit pattern for forward scanning
    # -----------------------------------------------------------------------
    # All supported units in one alternation
    _ALL_UNITS = (
        r'(?:'
        r'g\s*(?:\w+\s+)?(?:product\s*)?/\s*kg\s*(?:bw|body\s*weight)?\s*(?:/\s*(?:day|d))?'
        r'|mg\s*/\s*kg\s*(?:bw|body\s*weight)?\s*(?:/\s*(?:day|d))?'
        r'|mg\s*/\s*m\s*[³3]?\s*(?:/\s*(?:day|d))?'
        r'|mg\s*/\s*[Ll]'
        r'|m[Ll]\s*/\s*kg\s*(?:bw|body\s*weight)?\s*(?:/\s*(?:day|d))?'
        r'|\xb5g\s*/\s*kg\s*(?:bw|body\s*weight)?\s*(?:/\s*(?:day|d))?'
        r'|ppm'
        r'|%\s*(?:in\s+(?:the\s+)?(?:diet|feed|food|water))?'
        r')'
    )

    # Forward value+unit: optional qualifier, number, whitespace, unit
    # Qualifiers include symbols AND text: "more than", "greater than", "exceed", ">", ">="
    _QUAL_TEXT = r'(?:(?:more|greater|less)\s+than\s+|(?:to\s+)?exceed(?:s|ed|ing)?\s+|[><]=?\s*|[≥≤]\s*)?'
    _VAL_UNIT = re.compile(
        _QUAL_TEXT + _NUM + r'\s*(' + _ALL_UNITS + r')',
        re.IGNORECASE
    )

    # Connectors: patterns that bridge keyword to value.
    # Applied to the LOCAL window only (max ~300 chars), so .{1,100} is fine.
    _CONNECTORS = re.compile(
        r'(?:'
        r'(?:of|=|:)\s*'
        r'|(?:was|is|were)\s+(?:(?:determined|concluded|considered|reported|estimated|found)\s+(?:to\s+be|as)\s+)?'
        r'|(?:was|is|were)\s+(?:the\s+)?highest\s+dose\s+tested\s*[-\u2013\u2014,;]\s*'
        r'|(?:was|is|were)\s+'
        r'|(?:for|of|in)\s+.{1,100}?\s+(?:was|is|were)\s+(?:(?:determined|concluded|considered|reported|estimated|found)\s+(?:to\s+be|as)\s+)?'
        r'|(?:for|of|in)\s+.{1,100}?\s+(?:was|is|were)\s+(?:the\s+)?highest\s+dose\s+tested\s*[-\u2013\u2014,;]\s*'
        r'|(?:reported|observed|noted|identified|established)\s+(?:at|as)\s+'
        r'|\s+'
        r')',
        re.IGNORECASE
    )

    # -----------------------------------------------------------------------
    # Step 3: for each keyword hit, extract value from forward window
    # -----------------------------------------------------------------------
    for kw_match in kw_pattern.finditer(text):
        kw_text = kw_match.group(0)
        kw_end = kw_match.end()
        kw_start = kw_match.start()

        if _is_glossary_entry(text, kw_start):
            continue

        metric_key = _classify_keyword(kw_text)

        # Forward window: up to 300 chars after keyword end
        # Normalize whitespace so "mg/\nkg" becomes "mg/ kg" which matches unit regex
        window_end = min(len(text), kw_end + 300)
        window_raw = text[kw_end:window_end]
        window = re.sub(r'\s+', ' ', window_raw)

        # Try to find connector + value+unit in the window
        # First check if window starts with a connector
        conn_match = _CONNECTORS.match(window)
        if conn_match:
            after_conn = window[conn_match.end():]
            val_match = _VAL_UNIT.match(after_conn)
            if val_match:
                raw_val = val_match.group(1)
                unit_str = val_match.group(2).strip()
                value = _clean_value(raw_val)

                # Qualifier detection: look just before the number in the original text
                num_abs_pos = kw_end + conn_match.end()
                qualifier = _detect_qualifier(text, num_abs_pos)
                route = _detect_route(text, kw_start, kw_end + conn_match.end() + val_match.end())
                study_type = _detect_study_type(text, kw_start, kw_end + conn_match.end() + val_match.end())

                results[metric_key].append({
                    "value": value,
                    "unit": unit_str,
                    "route": route,
                    "qualifier": qualifier,
                    "study_type": study_type,
                })
                continue  # Found a match, move to next keyword

        # Fallback: scan the entire window for value+unit (catches bare patterns)
        val_match = _VAL_UNIT.search(window)
        if val_match:
            raw_val = val_match.group(1)
            unit_str = val_match.group(2).strip()
            value = _clean_value(raw_val)

            num_abs_pos = kw_end + val_match.start()
            qualifier = _detect_qualifier(text, num_abs_pos)
            route = _detect_route(text, kw_start, kw_end + val_match.end())
            study_type = _detect_study_type(text, kw_start, kw_end + val_match.end())

            results[metric_key].append({
                "value": value,
                "unit": unit_str,
                "route": route,
                "qualifier": qualifier,
                "study_type": study_type,
            })

    # -----------------------------------------------------------------------
    # Step 4: reverse patterns -- "50 mg/kg bw is an oral NOEL"
    # -----------------------------------------------------------------------
    reverse_pattern = re.compile(
        r'(?:[><]=?|[≥≤])?\s*' + _NUM + r'\s*(' + _ALL_UNITS + r')'
        r'.{0,60}?'
        r'(?:NOAEL|(?<![A-Za-z])NOEL(?![A-Za-z])|LOAEL|(?<![A-Za-z])LOEL(?![A-Za-z]))',
        re.IGNORECASE
    )

    for m in reverse_pattern.finditer(text):
        if _is_glossary_entry(text, m.start()):
            continue

        raw_val = m.group(1)
        unit_str = m.group(2).strip()
        value = _clean_value(raw_val)

        # Determine which metric from the keyword at end of match
        tail = m.group(0)[-10:].upper()
        if 'LOAEL' in tail:
            metric_key = "loael_values"
        elif 'LOEL' in tail:
            metric_key = "loel_values"
        elif 'NOAEL' in tail:
            metric_key = "noael_values"
        else:
            metric_key = "noel_values"

        num_match_inner = re.search(r'\d', m.group(0))
        num_pos = m.start() + (num_match_inner.start() if num_match_inner else 0)
        qualifier = _detect_qualifier(text, num_pos)
        route = _detect_route(text, m.start(), m.end())
        study_type = _detect_study_type(text, m.start(), m.end())

        results[metric_key].append({
            "value": value,
            "unit": unit_str,
            "route": route,
            "qualifier": qualifier,
            "study_type": study_type,
        })

    # -----------------------------------------------------------------------
    # Deduplicate each metric by value+unit+route
    # -----------------------------------------------------------------------
    for key in results:
        seen = set()
        unique = []
        for r in results[key]:
            dedup_key = f"{r['value']}_{r['unit']}_{r['route']}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                unique.append(r)
        results[key] = unique

    return results


def extract_noael_values(text: str) -> list[dict]:
    """
    Extract NOAEL values -- backwards-compatible wrapper.
    Returns a flat list of NOAEL dicts for the existing pipeline.
    """
    all_dose = extract_dose_values(text)
    combined = all_dose["noael_values"] + all_dose["noel_values"]

    seen = set()
    unique = []
    for r in combined:
        key = f"{r['value']}_{r['unit']}_{r['route']}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def extract_loael_values(text: str) -> list[dict]:
    """Extract LOAEL/LOEL values."""
    all_dose = extract_dose_values(text)
    combined = all_dose["loael_values"] + all_dose["loel_values"]
    seen = set()
    unique = []
    for r in combined:
        key = f"{r['value']}_{r['unit']}_{r['route']}"
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

    sccs_patterns = [
        (r'the\s+sccs\s+considers\s+.*?(safe|not\s+safe|unsafe|insufficient\s+data)', "sccs"),
        (r'the\s+sccs\s+is\s+of\s+the\s+opinion\s+that\s+.*?(safe|not\s+safe|unsafe)', "sccs"),
        (r'conclusion.*?(?:is|are)\s+(safe|not\s+safe|unsafe)', "sccs"),
    ]

    cir_patterns = [
        (r'the\s+(?:expert\s+)?panel\s+concluded\s+that\s+.*?(safe|not\s+safe|unsafe|insufficient)', "cir"),
        (r'(?:is|are)\s+safe\s+(?:in|for)\s+(?:use\s+in\s+)?cosmetics?\s+(?:in\s+the\s+present\s+practices)', "cir"),
    ]

    for pattern, source in sccs_patterns + cir_patterns:
        match = re.search(pattern, text_lower)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 200)
            conclusion_text = text[start:end].strip()
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
    match = re.search(r'(?:opinion|assessment)\s+(?:on|of)\s+(.+?)(?:\n|\(|CAS)', text[:2000], re.IGNORECASE)
    if match:
        name = match.group(1).strip()
        name = re.sub(r'\s+', ' ', name)
        if len(name) < 200:
            return name

    match = re.search(r'Safety\s+Assessment\s+of\s+(.+?)(?:\n|as\s+Used)', text[:2000], re.IGNORECASE)
    if match:
        name = match.group(1).strip()
        name = re.sub(r'\s+', ' ', name)
        if len(name) < 200:
            return name

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

    if source == "auto":
        if "SCCS" in text[:5000] or "sccs" in filename.lower():
            source = "sccs"
        elif "CIR" in text[:5000] or "Cosmetic Ingredient Review" in text[:5000]:
            source = "cir"
        else:
            source = "unknown"

    noael_vals = extract_noael_values(text)
    loael_vals = extract_loael_values(text)

    result = {
        "file": filename,
        "source": source,
        "ingredient_name": extract_ingredient_name(text, filename),
        "cas_numbers": extract_cas_numbers(text[:5000]),
        "noael_values": noael_vals,
        "loael_values": loael_vals,
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
  noael_qualifier TEXT,
  noael_study_type TEXT,
  loael_value REAL,
  loael_unit TEXT,
  loael_route TEXT,
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

        noael_list = r["noael_values"] if r["noael_values"] else [{"value": None, "unit": None, "route": None, "qualifier": "", "study_type": ""}]
        loael_list = r.get("loael_values", [])
        max_conc_list = r["max_concentrations"] if r["max_concentrations"] else [{"max_percent": None, "product_type": None}]

        best_loael = loael_list[0] if loael_list else {"value": None, "unit": None, "route": None}

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
                noael_qual = f"'{noael.get('qualifier', '')}'" if noael.get("qualifier") else "NULL"
                noael_study = f"'{noael.get('study_type', '')}'" if noael.get("study_type") else "NULL"

                loael_val = best_loael["value"] if best_loael.get("value") else "NULL"
                loael_unit = f"'{best_loael['unit']}'" if best_loael.get("unit") else "NULL"
                loael_route = f"'{best_loael['route']}'" if best_loael.get("route") else "NULL"

                max_pct = mc["max_percent"] if mc.get("max_percent") else "NULL"
                prod_type = f"'{mc['product_type']}'" if mc.get("product_type") else "NULL"

                cas_sql = f"'{cas}'" if cas else "NULL"
                ref_sql = f"'{ref}'" if ref else "NULL"

                sql_lines.append(
                    f"INSERT INTO {table} (source, ingredient_name, cas_number, sccs_reference, "
                    f"noael_value, noael_unit, noael_route, noael_qualifier, noael_study_type, "
                    f"loael_value, loael_unit, loael_route, "
                    f"max_concentration_percent, product_type, "
                    f"safety_verdict, conclusion_text, opinion_date, file_name) VALUES ("
                    f"'{r['source']}', '{name}', {cas_sql}, "
                    f"{ref_sql}, "
                    f"{noael_val}, {noael_unit}, {noael_route}, {noael_qual}, {noael_study}, "
                    f"{loael_val}, {loael_unit}, {loael_route}, "
                    f"{max_pct}, {prod_type}, "
                    f"'{verdict}', '{conclusion[:500]}', '{r['date']}', '{fname}');"
                )

    return "\n".join(sql_lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse-safety-opinions-v2.py <pdf_or_directory> [--source sccs|cir] [--output file.json] [--sql file.sql] [--limit N]")
        sys.exit(1)

    target = sys.argv[1]
    source = "auto"
    output = None
    sql_output = None
    limit = 0

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
    with_loael = sum(1 for r in results if "error" not in r and r.get("loael_values"))
    with_cas = sum(1 for r in results if "error" not in r and r.get("cas_numbers"))
    with_conc = sum(1 for r in results if "error" not in r and r.get("max_concentrations"))

    print(f"\n--- RESULTS ---")
    print(f"Total PDFs: {total}")
    print(f"Errors: {errors}")
    print(f"With NOAEL/NOEL: {with_noael}")
    print(f"With LOAEL/LOEL: {with_loael}")
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
