"""
Load Korea MFDS 1,291 prohibited ingredients into D1 jurisdiction_restrictions table.
Enriches English/INCI names by CAS matching against our 17K ingredient DB.
Replaces existing 121 KR records with the full official list.
"""
import csv, json, re, os

# Load CAS mapping from our ingredients DB
with open('C:/BENDA_PROJECT/roots-mcp-server/scripts/cas_map.json', 'r') as f:
    cas_map = json.load(f)

# Load Korea CSV
with open('C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/korea_prohibited_cosmetic_ingredients.csv', 'r', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

cas_pattern = re.compile(r'^\d{2,7}-\d{2}-\d$')

enriched = 0
sql_statements = []

# Delete existing KR records first
sql_statements.append("DELETE FROM jurisdiction_restrictions WHERE jurisdiction = 'KR';")

for row in rows:
    korean_name = row.get('Ingredient Name (Korean)', '').strip()
    english_name = row.get('Ingredient Name (English)', '').strip()
    cas_raw = row.get('CAS Number', '').strip()
    chem_name = row.get('Chemical Substance Name', '').strip()
    inci_name = row.get('INCI Name', '').strip()

    # Parse CAS - might have multiple separated by ;
    cas_numbers = []
    if cas_raw:
        for part in cas_raw.split(';'):
            part = part.strip()
            if cas_pattern.match(part):
                cas_numbers.append(part)

    cas_primary = cas_numbers[0] if cas_numbers else ''

    # Try to enrich from our DB
    matched_name = english_name
    matched_inci = inci_name

    if cas_primary and cas_primary in cas_map:
        db_entry = cas_map[cas_primary]
        if not matched_name and db_entry.get('name'):
            matched_name = db_entry['name']
            enriched += 1
        if not matched_inci and db_entry.get('inci'):
            matched_inci = db_entry['inci']

    # If still no English name, try chem_name or cas_raw (some have names in CAS field)
    if not matched_name:
        if chem_name and not cas_pattern.match(chem_name):
            matched_name = chem_name
        elif cas_raw and not cas_pattern.match(cas_raw.split(';')[0].strip()):
            matched_name = cas_raw

    # Build the ingredient name - prefer English, fall back to Korean
    ingredient_name = matched_name if matched_name else korean_name

    # Escape single quotes for SQL
    def esc(s):
        return s.replace("'", "''") if s else ''

    sql = f"""INSERT INTO jurisdiction_restrictions (jurisdiction, ingredient_name, inci_name, cas_number, status, max_concentration_percent, conditions, source) VALUES ('KR', '{esc(ingredient_name)}', '{esc(matched_inci)}', '{esc(cas_primary)}', 'prohibited', NULL, '{esc(korean_name)}', 'MFDS Prohibited Ingredients List (1,291 substances)');"""
    sql_statements.append(sql)

print(f"Total records: {len(rows)}")
print(f"Enriched from DB: {enriched}")
print(f"SQL statements: {len(sql_statements)}")

# Write SQL in batches (D1 has size limits)
batch_size = 100
os.makedirs('C:/BENDA_PROJECT/roots-mcp-server/scripts/korea-sql', exist_ok=True)

for i in range(0, len(sql_statements), batch_size):
    batch = sql_statements[i:i+batch_size]
    batch_num = i // batch_size
    filepath = f'C:/BENDA_PROJECT/roots-mcp-server/scripts/korea-sql/batch_{batch_num:03d}.sql'
    with open(filepath, 'w', encoding='utf-8', errors='replace') as f:
        f.write('\n'.join(batch))

num_batches = (len(sql_statements) + batch_size - 1) // batch_size
print(f"Written {num_batches} batch files to scripts/korea-sql/")
