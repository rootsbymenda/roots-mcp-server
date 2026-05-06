const fs = require('fs');
const { execFileSync } = require('child_process');
const path = require('path');

const DB_NAME = 'benda-ingredients';
const BATCH_SIZE = 50;

function escapeSQL(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'NULL';
  return "'" + String(val).replace(/'/g, "''").trim() + "'";
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

console.log('=== LOADING UK ===\n');

const ukPath = 'C:\\BENDA_PROJECT\\ROOTS_BY_BENDA\\11_INBOX\\20.2 downloads\\continue the day\\continue day 3 22.2\\UK_EU_Cosmetics_Divergence_Dataset - Main Dataset.csv';
const content = fs.readFileSync(ukPath, 'utf-8');
const lines = content.split('\n').filter(l => l.trim());

let headerIdx = -1;
for (let i = 0; i < lines.length; i++) {
  if (lines[i].includes('INCI_NAME')) { headerIdx = i; break; }
}

console.log('Header found at line ' + headerIdx);

const inserts = [];
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

  // Columns: [empty], INCI_NAME, CAS_NUMBER, EU_STATUS, UK_STATUS, DIFFERENCE_DESCRIPTION, UK_REGULATION_REFERENCE, EFFECTIVE_DATE_UK, DIVERGENCE_TYPE
  const inci = values[1] || '';
  if (!inci || inci === 'INCI_NAME' || inci.includes('Dataset') || inci.includes('Source')) continue;

  const cas = values[2] || '';
  const euStatus = values[3] || '';
  const ukStatus = values[4] || '';
  const diff = values[5] || '';
  const ukRef = values[6] || '';
  const effectiveDate = values[7] || '';
  const divType = values[8] || '';

  // Determine status from UK_STATUS field
  let status = 'restricted';
  const ukLower = ukStatus.toLowerCase();
  if (ukLower.includes('banned') || ukLower.includes('prohibited')) status = 'banned';
  else if (ukLower.includes('no action') || ukLower.includes('retained') || ukLower.includes('not adopted')) status = 'diverged_from_eu';
  else if (ukLower.includes('restricted')) status = 'restricted';

  const conditions = 'EU: ' + euStatus + ' | UK: ' + ukStatus + ' | Divergence: ' + diff;

  const sql = 'INSERT INTO jurisdiction_restrictions (jurisdiction, inci_name, cas_number, ingredient_name, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference, effective_date, source) VALUES (' +
    "'UK', " + escapeSQL(inci) + ', ' + escapeSQL(cas) + ', ' + escapeSQL(inci) + ', ' +
    escapeSQL(status) + ', NULL, NULL, ' + escapeSQL(conditions) + ', ' +
    escapeSQL(ukRef) + ', ' + escapeSQL(effectiveDate) + ", 'perplexity_deep_research');";
  inserts.push(sql);
}

console.log('Parsed ' + inserts.length + ' rows');
const total = pushBatch(inserts, 'uk');
console.log('=== UK DONE: ' + total + ' rows pushed ===');
