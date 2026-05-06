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

function parseCSVGeneric(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').filter(l => l.trim());

  let headerIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('inci_name') || lines[i].includes('INCI_NAME') || lines[i].includes('Ingredient')) {
      headerIdx = i; break;
    }
  }
  if (headerIdx === -1) { console.log('  No header found in ' + filePath); return []; }

  const headerLine = lines[headerIdx];
  const headers = [];
  let cur = ''; let inQ = false;
  for (let c = 0; c < headerLine.length; c++) {
    if (headerLine[c] === '"') inQ = !inQ;
    else if (headerLine[c] === ',' && !inQ) { headers.push(cur.trim()); cur = ''; }
    else cur += headerLine[c];
  }
  headers.push(cur.trim());

  const rows = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    const values = [];
    let current = ''; let inQuotes = false;
    for (let c = 0; c < line.length; c++) {
      if (line[c] === '"') inQuotes = !inQuotes;
      else if (line[c] === ',' && !inQuotes) { values.push(current.trim()); current = ''; }
      else current += line[c];
    }
    values.push(current.trim());

    const row = {};
    headers.forEach((h, idx) => { row[h] = values[idx] || ''; });
    rows.push(row);
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
    console.log('  ' + label + ' batch ' + batchNum + ' (' + batch.length + ' rows)...');
    try {
      execFileSync('npx', ['wrangler', 'd1', 'execute', DB_NAME, '--file=' + sqlFile, '--remote'], {
        cwd: path.join(__dirname, '..'), timeout: 60000, encoding: 'utf-8', shell: true
      });
      totalPushed += batch.length;
    } catch (err) {
      console.error('  ERROR batch ' + batchNum + ':', err.message.slice(0, 200));
    }
  }
  console.log('  ' + label + ': ' + totalPushed + '/' + inserts.length + ' pushed\n');
  return totalPushed;
}

console.log('=== LOADING CANADA (6 sheets) ===\n');
let totalAll = 0;

// 1. Prohibited
console.log('1. PROHIBITED');
const prohibRows = parseCSVGeneric(path.join(BASE, 'health_canada_cosmetic_hotlist_complete - Prohibited Ingredients.csv'));
console.log('  Parsed ' + prohibRows.length + ' rows');
let inserts = [];
for (const r of prohibRows) {
  const inci = r.inci_name || '';
  if (!inci || inci === 'inci_name') continue;
  const conds = [r.synonyms_related_compounds, r.reason_for_prohibition, r.canada_vs_eu_us_note].filter(Boolean).join('; ');
  const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'CA', " + escapeSQL(inci) + ', ' + escapeSQL(r.cas_number) + ', ' + escapeSQL(inci) + ', ' +
    escapeSQL(r.status || 'banned') + ', NULL, NULL, ' + escapeSQL(conds) + ', ' +
    escapeSQL(r.regulation_reference) + ", 'perplexity_deep_research');";
  inserts.push(sql);
}
totalAll += pushBatch(inserts, 'ca_prohib');

// 2. Restricted
console.log('2. RESTRICTED');
const restRows = parseCSVGeneric(path.join(BASE, 'health_canada_cosmetic_hotlist_complete - Restricted Ingredients.csv'));
console.log('  Parsed ' + restRows.length + ' rows');
inserts = [];
for (const r of restRows) {
  const inci = r.inci_name || '';
  if (!inci || inci === 'inci_name') continue;
  const conds = [r.conditions, r.canada_vs_eu_us_note].filter(Boolean).join('; ');
  const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'CA', " + escapeSQL(inci) + ', ' + escapeSQL(r.cas_number) + ', ' + escapeSQL(inci) + ', ' +
    escapeSQL(r.status || 'restricted') + ', ' + escapeSQL(r.max_concentration_percent) + ', ' +
    escapeSQL(r.product_type_restriction) + ', ' + escapeSQL(conds) + ', ' +
    escapeSQL(r.regulation_reference) + ", 'perplexity_deep_research');";
  inserts.push(sql);
}
totalAll += pushBatch(inserts, 'ca_restrict');

// 3. Heavy Metal Limits
console.log('3. HEAVY METAL LIMITS');
const hmRows = parseCSVGeneric(path.join(BASE, 'health_canada_cosmetic_hotlist_complete - Heavy Metal Limits.csv'));
console.log('  Parsed ' + hmRows.length + ' rows');
inserts = [];
for (const r of hmRows) {
  const inci = r.inci_name || r['Metal / Contaminant'] || r[''] || '';
  if (!inci || inci.includes('Metal') || inci.includes('HEALTH')) continue;
  // Try to find data in any column
  const vals = Object.values(r).filter(Boolean);
  if (vals.length < 2) continue;
  const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'CA', " + escapeSQL(inci) + ', ' + escapeSQL(r.cas_number || '') + ', ' + escapeSQL(inci) + ', ' +
    "'restricted', " + escapeSQL(r.max_concentration_percent || r.limit_ppm || '') + ', NULL, ' +
    escapeSQL(vals.slice(1).join('; ')) + ', ' + escapeSQL(r.regulation_reference || 'Health Canada Heavy Metal Guidance') +
    ", 'perplexity_deep_research');";
  inserts.push(sql);
}
if (inserts.length > 0) totalAll += pushBatch(inserts, 'ca_hm');
else console.log('  Skipped (parse issue)\n');

// 4. NHP-Drug Crossover
console.log('4. NHP-DRUG CROSSOVER');
const nhpRows = parseCSVGeneric(path.join(BASE, 'health_canada_cosmetic_hotlist_complete - NHP-Drug Crossover.csv'));
console.log('  Parsed ' + nhpRows.length + ' rows');
inserts = [];
for (const r of nhpRows) {
  const inci = r.inci_name || r.Ingredient || '';
  if (!inci || inci.includes('NATURAL') || inci.includes('Ingredient')) continue;
  const vals = Object.values(r).filter(Boolean);
  if (vals.length < 2) continue;
  const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'CA', " + escapeSQL(inci) + ', ' + escapeSQL(r.cas_number || '') + ', ' + escapeSQL(inci) + ', ' +
    "'drug_classification', NULL, NULL, " + escapeSQL(vals.slice(1).join('; ')) + ', ' +
    escapeSQL(r.regulation_reference || 'Health Canada NHP/Drug Classification') +
    ", 'perplexity_deep_research');";
  inserts.push(sql);
}
if (inserts.length > 0) totalAll += pushBatch(inserts, 'ca_nhp');
else console.log('  Skipped (parse issue)\n');

// 5. 2024-2026 Updates
console.log('5. 2024-2026 UPDATES');
const updRows = parseCSVGeneric(path.join(BASE, 'health_canada_cosmetic_hotlist_complete - 2024-2026 Updates.csv'));
console.log('  Parsed ' + updRows.length + ' rows');
inserts = [];
for (const r of updRows) {
  const inci = r.inci_name || '';
  if (!inci || inci === 'inci_name' || inci.includes('HEALTH')) continue;
  const vals = Object.values(r).filter(Boolean);
  if (vals.length < 2) continue;
  const status = (r.status || '').toLowerCase() || 'updated';
  if (status === 'updated' || !status) continue; // skip non-actionable
  const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'CA', " + escapeSQL(inci) + ', ' + escapeSQL(r.cas_number || '') + ', ' + escapeSQL(inci) + ', ' +
    escapeSQL(status) + ', ' + escapeSQL(r.max_concentration_percent || '') + ', ' +
    escapeSQL(r.product_type_restriction || '') + ', ' + escapeSQL(r.conditions || vals.slice(1).join('; ')) + ', ' +
    escapeSQL(r.regulation_reference || 'Health Canada Hotlist Update 2024-2026') +
    ", 'perplexity_deep_research');";
  inserts.push(sql);
}
if (inserts.length > 0) totalAll += pushBatch(inserts, 'ca_upd');
else console.log('  Skipped (no actionable rows)\n');

console.log('=== CANADA TOTAL: ' + totalAll + ' rows pushed ===');
