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
      execFileSync('npx', ['wrangler', 'd1', 'execute', DB_NAME, '--file=' + sqlFile, '--remote'], {
        cwd: path.join(__dirname, '..'),
        timeout: 60000,
        encoding: 'utf-8',
        shell: true
      });
      totalPushed += batch.length;
    } catch (err) {
      console.error('  ERROR on batch ' + batchNum + ':', err.message.slice(0, 200));
    }
  }
  console.log('  ' + label + ': ' + totalPushed + '/' + inserts.length + ' rows pushed\n');
  return totalPushed;
}

console.log('=== LOADING MORE JURISDICTIONS ===\n');
let totalAll = 0;

// AUSTRALIA
console.log('1. AUSTRALIA (from CSV)');
const auPath = 'C:\\BENDA_PROJECT\\ROOTS_BY_BENDA\\11_INBOX\\27.2.2\\australia_cosmetic_ingredients_regulations.csv';
if (fs.existsSync(auPath)) {
  const rows = parseCSV(auPath);
  console.log('  Parsed ' + rows.length + ' rows');
  const inserts = [];
  for (const row of rows) {
    const inci = row.inci_name || '';
    if (!inci || inci === 'inci_name') continue;
    const conds = [row.schedule_classification, row.conditions].filter(Boolean).join('; ');
    const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
      "'AU', " + escapeSQL(inci) + ', ' + escapeSQL(row.cas_number) + ', ' + escapeSQL(inci) + ', ' +
      escapeSQL(row.status) + ', ' + escapeSQL(row.max_concentration_percent) + ', ' +
      escapeSQL(row.product_type_restriction) + ', ' + escapeSQL(conds) + ', ' +
      escapeSQL(row.regulation_reference) + ", 'perplexity_deep_research');";
    inserts.push(sql);
  }
  totalAll += pushBatch(inserts, 'au');
}

console.log('\n=== TOTAL THIS RUN: ' + totalAll + ' rows pushed ===');
