const fs = require('fs');
const { execFileSync } = require('child_process');
const path = require('path');

const DB_NAME = 'benda-ingredients';
const BATCH_SIZE = 50;

function escapeSQL(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'NULL';
  return "'" + String(val).replace(/'/g, "''").trim() + "'";
}

function parseCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').filter(l => l.trim());

  let headerIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('inci_name')) { headerIdx = i; break; }
  }
  if (headerIdx === -1) { console.log('No header found!'); return []; }

  const headers = lines[headerIdx].split(',').map(h => h.trim().replace(/^"|"$/g, ''));

  const rows = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
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

    const row = {};
    headers.forEach((h, idx) => { row[h] = values[idx] || ''; });

    // Handle offset (empty first column)
    const inci = row.inci_name || values[1] || '';
    if (inci && inci !== 'inci_name' && !inci.includes('Dataset') && !inci.includes('Source')) {
      row._inci = inci;
      row._cas = row.cas_number || values[2] || '';
      row._status = (row.status || values[3] || '').toLowerCase();
      row._max = row.max_concentration_percent || values[4] || '';
      row._grade = row.product_grade || values[5] || '';
      row._type = row.product_type_restriction || values[6] || '';
      row._cond = row.conditions || values[7] || '';
      row._ref = row.regulation_reference || values[8] || '';
      if (row._status) rows.push(row);
    }
  }
  return rows;
}

function pushBatch(inserts, label) {
  const tmpDir = path.join(__dirname, '..', 'tmp_jurisdiction');
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });

  let totalPushed = 0;
  let batchNum = 0;

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

console.log('=== LOADING BRAZIL ===\n');

const brPath = 'C:\\BENDA_PROJECT\\ROOTS_BY_BENDA\\11_INBOX\\20.2 downloads\\continue the day\\continue day 3 22.2\\ANVISA_Brazil_Cosmetics_Regulatory_Dataset - Complete Dataset.csv';
const rows = parseCSV(brPath);
console.log('Parsed ' + rows.length + ' rows');

const inserts = [];
for (const row of rows) {
  const conds = [row._grade ? 'Grade: ' + row._grade : '', row._cond].filter(Boolean).join('; ');
  const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    "'BR', " + escapeSQL(row._inci) + ', ' + escapeSQL(row._cas) + ', ' + escapeSQL(row._inci) + ', ' +
    escapeSQL(row._status) + ', ' + escapeSQL(row._max) + ', ' +
    escapeSQL(row._type) + ', ' + escapeSQL(conds) + ', ' +
    escapeSQL(row._ref) + ", 'perplexity_deep_research');";
  inserts.push(sql);
}

const total = pushBatch(inserts, 'br');
console.log('=== BRAZIL DONE: ' + total + ' rows pushed ===');
