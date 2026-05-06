const fs = require('fs');
const { execFileSync, execSync } = require('child_process');

function parseRow(line) {
  const f = []; let fd = '', q = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') { q = !q; }
    else if (line[i] === ',' && !q) { f.push(fd); fd = ''; }
    else { fd += line[i]; }
  }
  f.push(fd);
  return f;
}

function esc(v) {
  if (!v || !v.trim()) return 'NULL';
  return "'" + v.trim().replace(/'/g, "''").substring(0, 1500) + "'";
}

function importCSV(file, table, label) {
  console.log('\n=== ' + label + ' ===');
  const raw = fs.readFileSync(file, 'utf8');
  const lines = raw.replace(/^\uFEFF/, '').split('\n').filter(l => l.trim());
  const cols = parseRow(lines[0]).map(c => c.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/_+/g, '_'));
  const rows = lines.slice(1);

  let sql = 'DROP TABLE IF EXISTS ' + table + ';\n';
  sql += 'CREATE TABLE ' + table + ' (id INTEGER PRIMARY KEY AUTOINCREMENT, ' + cols.map(c => c + ' TEXT').join(', ') + ');\n';

  for (let i = 0; i < rows.length; i += 100) {
    const batch = rows.slice(i, i + 100).filter(r => r.trim());
    if (!batch.length) continue;
    const vals = batch.map(r => {
      const f = parseRow(r);
      return '(' + cols.map((_, j) => esc(f[j] || '')).join(',') + ')';
    }).join(',\n');
    sql += 'INSERT INTO ' + table + ' (' + cols.join(',') + ') VALUES ' + vals + ';\n';
  }

  fs.writeFileSync('tmp_water.sql', sql);
  try {
    execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_water.sql'], { stdio: 'pipe', shell: true });
  } catch(e) {
    console.log('RETRY...');
    execSync('sleep 15');
    execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_water.sql'], { stdio: 'pipe', shell: true });
  }
  try { fs.unlinkSync('tmp_water.sql'); } catch(e) {}
  console.log('DONE: ' + rows.length + ' rows');
  return rows.length;
}

const B = 'C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/';
let t = 0;
t += importCSV(B + 'EPA_National_Primary_Drinking_Water_Regulations_MCLs.csv', 'epa_drinking_water_mcls', 'EPA MCLs');
t += importCSV(B + 'WHO_GDWQ_4th_Edition_2022_Chemical_Guideline_Values.csv', 'who_drinking_water_guidelines', 'WHO GDWQ');
t += importCSV(B + 'EU_Drinking_Water_Directive_2020_2184_Parametric_Values.csv', 'eu_drinking_water_directive', 'EU DWD');
t += importCSV(B + 'health_canada_drinking_water_guidelines.csv', 'health_canada_drinking_water', 'Health Canada DW');
t += importCSV(B + 'EPA_CCL5_UCMR5_Contaminants.csv', 'epa_ccl5_ucmr5', 'EPA CCL5+UCMR5');
t += importCSV(B + 'drinking_water_quality_standards_australia_japan.csv', 'water_standards_au_jp', 'Australia+Japan');

console.log('\n=== ALL DONE === Total: ' + t + ' rows');
