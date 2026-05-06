const fs = require('fs');
const { execFileSync } = require('child_process');
const path = require('path');

const DB_NAME = 'benda-ingredients';
const BATCH_SIZE = 50;
const BASE = 'C:\\BENDA_PROJECT\\ROOTS_BY_BENDA\\11_INBOX\\20.2 downloads\\continue the day\\continue day 3 22.2';

function escapeSQL(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'NULL';
  return "'" + String(val).replace(/'/g, "''").trim() + "'";
}

function smartParseCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');

  // Find header line containing 'inci_name'
  let headerIdx = -1;
  for (let i = 0; i < Math.min(lines.length, 15); i++) {
    if (lines[i].includes('inci_name')) { headerIdx = i; break; }
  }
  if (headerIdx === -1) return [];

  // Parse with proper CSV handling
  function parseLine(line) {
    const values = [];
    let current = '';
    let inQuotes = false;
    for (let c = 0; c < line.length; c++) {
      const ch = line[c];
      if (ch === '"') { inQuotes = !inQuotes; }
      else if (ch === ',' && !inQuotes) { values.push(current.replace(/\r/g, '').trim()); current = ''; }
      else if (ch !== '\r') { current += ch; }
    }
    values.push(current.replace(/\r/g, '').trim());
    return values;
  }

  const headers = parseLine(lines[headerIdx]);
  // Find the inci_name column index
  const inciIdx = headers.indexOf('inci_name');
  if (inciIdx === -1) return [];

  const rows = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
    if (!lines[i] || !lines[i].trim()) continue;
    const vals = parseLine(lines[i]);
    const row = {};
    headers.forEach((h, idx) => {
      if (h) row[h] = vals[idx] || '';
    });
    if (row.inci_name && row.inci_name !== 'inci_name') rows.push(row);
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
    process.stdout.write('  ' + label + ' batch ' + batchNum + ' (' + batch.length + ')... ');
    try {
      execFileSync('npx', ['wrangler', 'd1', 'execute', DB_NAME, '--file=' + sqlFile, '--remote'], {
        cwd: path.join(__dirname, '..'), timeout: 60000, encoding: 'utf-8', shell: true
      });
      totalPushed += batch.length;
      console.log('OK');
    } catch (err) {
      console.log('ERR');
      console.error('    ' + err.message.slice(0, 150));
    }
  }
  console.log('  TOTAL ' + label + ': ' + totalPushed + '/' + inserts.length + '\n');
  return totalPushed;
}

console.log('=== LOADING CANADA ===\n');
let totalAll = 0;

// 1. Prohibited
console.log('--- PROHIBITED ---');
const pRows = smartParseCSV(path.join(BASE, 'health_canada_cosmetic_hotlist_complete - Prohibited Ingredients.csv'));
console.log('Parsed: ' + pRows.length);
if (pRows.length > 0) console.log('Sample:', JSON.stringify(pRows[0]).slice(0, 200));
let ins = [];
for (const r of pRows) {
  const conds = [r.synonyms_related_compounds, r.reason_for_prohibition, r.canada_vs_eu_us_note].filter(Boolean).join('; ');
  ins.push('INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'CA', " + escapeSQL(r.inci_name) + ', ' + escapeSQL(r.cas_number) + ', ' + escapeSQL(r.inci_name) + ', ' +
    "'banned', NULL, NULL, " + escapeSQL(conds) + ', ' + escapeSQL(r.regulation_reference) + ", 'perplexity_deep_research');");
}
totalAll += pushBatch(ins, 'ca_p');

// 2. Restricted
console.log('--- RESTRICTED ---');
const rRows = smartParseCSV(path.join(BASE, 'health_canada_cosmetic_hotlist_complete - Restricted Ingredients.csv'));
console.log('Parsed: ' + rRows.length);
if (rRows.length > 0) console.log('Sample:', JSON.stringify(rRows[0]).slice(0, 200));
ins = [];
for (const r of rRows) {
  const conds = [r.conditions, r.canada_vs_eu_us_note].filter(Boolean).join('; ');
  ins.push('INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'CA', " + escapeSQL(r.inci_name) + ', ' + escapeSQL(r.cas_number) + ', ' + escapeSQL(r.inci_name) + ', ' +
    "'restricted', " + escapeSQL(r.max_concentration_percent) + ', ' + escapeSQL(r.product_type_restriction) + ', ' +
    escapeSQL(conds) + ', ' + escapeSQL(r.regulation_reference) + ", 'perplexity_deep_research');");
}
totalAll += pushBatch(ins, 'ca_r');

// 3. NHP-Drug Crossover
console.log('--- NHP-DRUG CROSSOVER ---');
const nRows = smartParseCSV(path.join(BASE, 'health_canada_cosmetic_hotlist_complete - NHP-Drug Crossover.csv'));
console.log('Parsed: ' + nRows.length);
if (nRows.length > 0) console.log('Sample:', JSON.stringify(nRows[0]).slice(0, 200));
ins = [];
for (const r of nRows) {
  const conds = Object.entries(r).filter(([k,v]) => k !== 'inci_name' && k !== 'cas_number' && v).map(([k,v]) => k + ': ' + v).join('; ');
  ins.push('INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'CA', " + escapeSQL(r.inci_name) + ', ' + escapeSQL(r.cas_number || '') + ', ' + escapeSQL(r.inci_name) + ', ' +
    "'drug_classification', NULL, NULL, " + escapeSQL(conds) + ', ' +
    escapeSQL(r.regulation_reference || 'Health Canada NHP/Drug Classification') + ", 'perplexity_deep_research');");
}
if (ins.length > 0) totalAll += pushBatch(ins, 'ca_n');

console.log('=== CANADA TOTAL: ' + totalAll + ' rows pushed ===');
