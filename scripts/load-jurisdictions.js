const fs = require('fs');
const { execFileSync } = require('child_process');
const path = require('path');

const DB_NAME = 'benda-ingredients';
const BATCH_SIZE = 50;

function escapeSQL(val) {
  if (val === null || val === undefined || val === '') return 'NULL';
  return "'" + String(val).replace(/'/g, "''").trim() + "'";
}

function parseCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').filter(l => l.trim());
  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const values = [];
    let current = '';
    let inQuotes = false;
    for (let c = 0; c < line.length; c++) {
      if (line[c] === '"') {
        inQuotes = !inQuotes;
      } else if (line[c] === ',' && !inQuotes) {
        values.push(current.trim());
        current = '';
      } else {
        current += line[c];
      }
    }
    values.push(current.trim());

    if (values.length >= 2) {
      const row = {};
      headers.forEach((h, idx) => { row[h] = values[idx] || ''; });
      rows.push(row);
    }
  }
  return rows;
}

function generateInserts(jurisdiction, rows) {
  const inserts = [];
  for (const row of rows) {
    const inci = row.inci_name || row.INCI_Name || '';
    if (!inci || inci === '#' || inci === 'inci_name') continue;

    const sql = `INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (${escapeSQL(jurisdiction)}, ${escapeSQL(inci)}, ${escapeSQL(row.cas_number)}, ${escapeSQL(row.ingredient_name || inci)}, ${escapeSQL(row.status)}, ${escapeSQL(row.max_concentration_percent)}, ${escapeSQL(row.product_type_restriction)}, ${escapeSQL(row.conditions)}, ${escapeSQL(row.regulation_reference)}, 'perplexity_deep_research');`;
    inserts.push(sql);
  }
  return inserts;
}

function parseJapanKoreaSQL(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const inserts = [];
  const regex = /VALUES \('([^']*)',\s*'([^']*)',\s*(?:'([^']*)'|NULL),\s*(?:'([^']*)'|NULL),\s*'([^']*)',\s*(?:'([^']*)'|NULL),\s*(?:'([^']*)'|NULL),\s*(?:'([^']*)'|NULL),\s*(?:'([^']*)'|NULL),\s*(?:'([^']*)'|NULL)\)/g;

  let match;
  while ((match = regex.exec(content)) !== null) {
    const [, jurisdiction, ingredient_name, inci_name, cas_number, restriction_type, max_concentration, product_type_restriction, ingredient_category, regulation_reference, notes] = match;

    const status = restriction_type.toLowerCase().includes('prohibit') ? 'banned' :
                   restriction_type.toLowerCase().includes('restrict') ? 'restricted' :
                   restriction_type.toLowerCase();

    const jCode = jurisdiction === 'Japan' ? 'JP' : jurisdiction === 'Korea' ? 'KR' : jurisdiction;

    const sql = `INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (${escapeSQL(jCode)}, ${escapeSQL(inci_name || ingredient_name)}, ${escapeSQL(cas_number)}, ${escapeSQL(ingredient_name)}, ${escapeSQL(status)}, ${escapeSQL(max_concentration)}, ${escapeSQL(product_type_restriction)}, ${escapeSQL(notes ? ingredient_category + '; ' + notes : ingredient_category)}, ${escapeSQL(regulation_reference)}, 'prepared_sql');`;
    inserts.push(sql);
  }
  return inserts;
}

function pushBatch(inserts, label) {
  const tmpDir = path.join(__dirname, '..', 'tmp_jurisdiction');
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });

  let batchNum = 0;
  let totalPushed = 0;

  for (let i = 0; i < inserts.length; i += BATCH_SIZE) {
    batchNum++;
    const batch = inserts.slice(i, i + BATCH_SIZE);
    const sqlFile = path.join(tmpDir, label + '_batch_' + batchNum + '.sql');
    fs.writeFileSync(sqlFile, batch.join('\n'));

    console.log('  Pushing ' + label + ' batch ' + batchNum + ' (' + batch.length + ' rows)...');
    try {
      const result = execFileSync('npx', ['wrangler', 'd1', 'execute', DB_NAME, '--file=' + sqlFile, '--remote'], {
        cwd: path.join(__dirname, '..'),
        timeout: 60000,
        encoding: 'utf-8',
        shell: true
      });
      totalPushed += batch.length;
      const m = result.match(/Rows written:\s*(\d+)/);
      if (m) console.log('    -> ' + m[1] + ' rows written');
    } catch (err) {
      console.error('  ERROR on batch ' + batchNum + ':', err.message.slice(0, 200));
    }
  }
  console.log('  ' + label + ': ' + totalPushed + '/' + inserts.length + ' rows pushed\n');
  return totalPushed;
}

// ============ MAIN ============

console.log('=== JURISDICTION DATA LOADER ===\n');

let totalAll = 0;

// 1. Japan/Korea
console.log('1. JAPAN + KOREA (from tmp_jk.sql)');
const jkPath = path.join(__dirname, '..', 'tmp_jk.sql');
if (fs.existsSync(jkPath)) {
  const jkInserts = parseJapanKoreaSQL(jkPath);
  console.log('  Parsed ' + jkInserts.length + ' rows');
  totalAll += pushBatch(jkInserts, 'jp_kr');
} else {
  console.log('  File not found, skipping');
}

// 2. China
console.log('2. CHINA (from CSV)');
const cnPath = 'C:\\BENDA_PROJECT\\ROOTS_BY_BENDA\\11_INBOX\\27.2.2\\china_nmpa_cosmetic_ingredients.csv';
if (fs.existsSync(cnPath)) {
  const cnRows = parseCSV(cnPath);
  console.log('  Parsed ' + cnRows.length + ' rows');
  const cnInserts = generateInserts('CN', cnRows);
  totalAll += pushBatch(cnInserts, 'cn');
} else {
  console.log('  File not found, skipping');
}

// 3. India
console.log('3. INDIA (from CSV)');
const inPath = 'C:\\BENDA_PROJECT\\ROOTS_BY_BENDA\\11_INBOX\\27.2.2\\India_CDSCO_Cosmetic_Ingredients.csv';
if (fs.existsSync(inPath)) {
  const inRows = parseCSV(inPath);
  console.log('  Parsed ' + inRows.length + ' rows');
  const inInserts = generateInserts('IN', inRows);
  totalAll += pushBatch(inInserts, 'in');
} else {
  console.log('  File not found, skipping');
}

console.log('\n=== TOTAL: ' + totalAll + ' rows pushed to jurisdiction_restrictions ===');
