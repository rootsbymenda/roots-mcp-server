const fs = require('fs');
const { execFileSync } = require('child_process');
const path = require('path');

const DB_NAME = 'benda-ingredients';
const BATCH_SIZE = 50;

function escapeSQL(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'NULL';
  return "'" + String(val).replace(/'/g, "''").trim() + "'";
}

function parseGCCCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').filter(l => l.trim());

  // Find the header row (contains "INCI Name")
  let headerIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('INCI Name')) { headerIdx = i; break; }
  }
  if (headerIdx === -1) { console.log('No header found!'); return []; }

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

    // Columns: [empty], INCI Name, CAS Number, Jurisdiction, Status, Max Conc. (%), Product Type Restriction, Conditions / Notes, Regulation Reference
    const inci = values[1] || '';
    if (!inci || inci === 'INCI Name' || inci.includes('Full Dataset')) continue;

    rows.push({
      inci_name: inci,
      cas_number: values[2] || '',
      jurisdiction: values[3] || 'GCC',
      status: (values[4] || '').toLowerCase(),
      max_concentration_percent: values[5] || '',
      product_type_restriction: values[6] || '',
      conditions: values[7] || '',
      regulation_reference: values[8] || ''
    });
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

console.log('=== LOADING GCC ===\n');

const gccPath = 'C:\\BENDA_PROJECT\\ROOTS_BY_BENDA\\11_INBOX\\20.2 downloads\\continue the day\\continue day 3 22.2\\GCC_Cosmetics_Regulatory_Dataset - Full Dataset.csv';
const rows = parseGCCCSV(gccPath);
console.log('Parsed ' + rows.length + ' rows');

// Show jurisdiction breakdown
const jBreak = {};
rows.forEach(r => { jBreak[r.jurisdiction] = (jBreak[r.jurisdiction] || 0) + 1; });
console.log('Jurisdictions:', JSON.stringify(jBreak));

const inserts = [];
for (const row of rows) {
  const jCode = row.jurisdiction.includes('Saudi') ? 'SA' :
                row.jurisdiction.includes('UAE') ? 'AE' :
                row.jurisdiction.includes('GCC') ? 'GCC' :
                row.jurisdiction;
  const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, source) VALUES (' +
    escapeSQL(jCode) + ', ' + escapeSQL(row.inci_name) + ', ' + escapeSQL(row.cas_number) + ', ' + escapeSQL(row.inci_name) + ', ' +
    escapeSQL(row.status) + ', ' + escapeSQL(row.max_concentration_percent) + ', ' +
    escapeSQL(row.product_type_restriction) + ', ' + escapeSQL(row.conditions) + ', ' +
    escapeSQL(row.regulation_reference) + ", 'perplexity_deep_research');";
  inserts.push(sql);
}

const total = pushBatch(inserts, 'gcc');
console.log('=== GCC DONE: ' + total + ' rows pushed ===');
