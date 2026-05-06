const fs = require('fs');
const { execFileSync } = require('child_process');
const path = require('path');

const DB_NAME = 'benda-ingredients';
const BATCH_SIZE = 50;
const BASE = 'C:\\BENDA_PROJECT\\ROOTS_BY_BENDA\\11_INBOX\\20.2 downloads\\continue the day\\continue day 3 22.2';

function escapeSQL(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'NULL';
  return "'" + String(val).replace(/'/g, "''").replace(/\r/g, '').trim() + "'";
}

function smartParseCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  let headerIdx = -1;
  for (let i = 0; i < Math.min(lines.length, 15); i++) {
    if (lines[i].includes('inci_name') || lines[i].includes('INCI') || lines[i].includes('common_name')) { headerIdx = i; break; }
  }
  if (headerIdx === -1) return [];

  function parseLine(line) {
    const values = [];
    let current = ''; let inQuotes = false;
    for (let c = 0; c < line.length; c++) {
      const ch = line[c];
      if (ch === '"') inQuotes = !inQuotes;
      else if (ch === ',' && !inQuotes) { values.push(current.replace(/\r/g, '').trim()); current = ''; }
      else if (ch !== '\r') current += ch;
    }
    values.push(current.replace(/\r/g, '').trim());
    return values;
  }

  const headers = parseLine(lines[headerIdx]);
  const rows = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
    if (!lines[i] || !lines[i].trim()) continue;
    const vals = parseLine(lines[i]);
    const row = {};
    headers.forEach((h, idx) => { if (h) row[h] = vals[idx] || ''; });
    // Get inci from multiple possible column names
    const inci = row['inci_name'] || row['inci_name / common_name'] || '';
    if (inci && !inci.includes('ACD') && !inci.includes('ASEAN') && !inci.includes('Source:')) {
      row._inci = inci;
      rows.push(row);
    }
  }
  return rows;
}

function pushBatch(inserts, label) {
  const tmpDir = path.join(__dirname, '..', 'tmp_jurisdiction');
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
  let totalPushed = 0; let batchNum = 0;
  for (let i = 0; i < inserts.length; i += BATCH_SIZE) {
    batchNum++;
    const batch = inserts.slice(i, i + BATCH_SIZE);
    const sqlFile = path.join(tmpDir, label + '_batch_' + batchNum + '.sql');
    fs.writeFileSync(sqlFile, batch.join('\n'));
    process.stdout.write('  ' + label + ' b' + batchNum + '(' + batch.length + ')...');
    try {
      execFileSync('npx', ['wrangler', 'd1', 'execute', DB_NAME, '--file=' + sqlFile, '--remote'], {
        cwd: path.join(__dirname, '..'), timeout: 60000, encoding: 'utf-8', shell: true
      });
      totalPushed += batch.length;
      console.log('OK');
    } catch (err) { console.log('ERR: ' + err.message.slice(0, 100)); }
  }
  console.log('  ' + label + ': ' + totalPushed + '/' + inserts.length + '\n');
  return totalPushed;
}

console.log('=== LOADING ASEAN ===\n');
let totalAll = 0;

const sheets = [
  { file: 'ACD_Cosmetic_Ingredients_Database_2024_2026 - Ann II — Banned.csv', defaultStatus: 'banned', label: 'asean_ban' },
  { file: 'ACD_Cosmetic_Ingredients_Database_2024_2026 - Ann III — Restricted.csv', defaultStatus: 'restricted', label: 'asean_restr' },
  { file: 'ACD_Cosmetic_Ingredients_Database_2024_2026 - Ann VI — Preservatives.csv', defaultStatus: 'permitted_preservative', label: 'asean_pres' },
  { file: 'ACD_Cosmetic_Ingredients_Database_2024_2026 - Ann VII — UV Filters.csv', defaultStatus: 'permitted_uv_filter', label: 'asean_uv' },
  { file: 'ACD_Cosmetic_Ingredients_Database_2024_2026 - Ann IV — Colorants.csv', defaultStatus: 'permitted_colorant', label: 'asean_color' },
  { file: 'ACD_Cosmetic_Ingredients_Database_2024_2026 - Country Exceptions.csv', defaultStatus: 'country_exception', label: 'asean_except' },
];

for (const sheet of sheets) {
  console.log('--- ' + sheet.label.toUpperCase() + ' ---');
  const rows = smartParseCSV(path.join(BASE, sheet.file));
  console.log('Parsed: ' + rows.length);

  const inserts = [];
  for (const r of rows) {
    const status = (r.status || sheet.defaultStatus).toLowerCase();
    if (!status) continue;
    const maxConc = r['max_concentration_%'] || r.max_concentration_percent || '';
    const prodType = r.product_type || r.product_restriction || '';
    const conds = [r.conditions, r.label_requirements, r.notes_2024_2026, r.notes_vs_asean, r.colour_index].filter(Boolean).join('; ');
    const appliesTo = r.applies_to || r.country || 'ASEAN-wide';
    const jCode = appliesTo.includes('Indonesia') ? 'ID' :
                  appliesTo.includes('Thailand') ? 'TH' :
                  appliesTo.includes('Malaysia') ? 'MY' :
                  appliesTo.includes('Philippines') ? 'PH' :
                  appliesTo.includes('Singapore') ? 'SG' :
                  appliesTo.includes('Vietnam') ? 'VN' : 'ASEAN';

    inserts.push('INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
      escapeSQL(jCode) + ', ' + escapeSQL(r._inci) + ', ' + escapeSQL(r.cas_number || '') + ', ' + escapeSQL(r._inci) + ', ' +
      escapeSQL(status) + ', ' + escapeSQL(maxConc) + ', ' + escapeSQL(prodType) + ', ' +
      escapeSQL(conds) + ', ' + escapeSQL(r.regulation_reference || 'ASEAN Cosmetic Directive') + ", 'perplexity_deep_research');");
  }
  if (inserts.length > 0) totalAll += pushBatch(inserts, sheet.label);
  else console.log('  (no valid rows)\n');
}

console.log('=== ASEAN TOTAL: ' + totalAll + ' rows pushed ===');
