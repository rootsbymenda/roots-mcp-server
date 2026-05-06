const fs = require('fs');
const { execFileSync } = require('child_process');
const raw = fs.readFileSync('C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/ZDHC_MRSL_V3.1_Full_Restricted_Substances.csv', 'utf8');
const lines = raw.replace(/^\uFEFF/, '').split('\n').filter(l => l.trim());

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

const cols = parseRow(lines[0]).map(c => c.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/_+/g, '_'));
const rows = lines.slice(1);
console.log('Columns: ' + cols.length + ', Rows: ' + rows.length);

let sql = 'DROP TABLE IF EXISTS zdhc_mrsl;\n';
sql += 'CREATE TABLE zdhc_mrsl (id INTEGER PRIMARY KEY AUTOINCREMENT, ' + cols.map(c => c + ' TEXT').join(', ') + ');\n';

for (let i = 0; i < rows.length; i += 50) {
  const batch = rows.slice(i, i + 50).filter(r => r.trim());
  if (!batch.length) continue;
  const vals = batch.map(r => {
    const f = parseRow(r);
    return '(' + cols.map((_, j) => esc(f[j] || '')).join(',') + ')';
  }).join(',\n');
  sql += 'INSERT INTO zdhc_mrsl (' + cols.join(',') + ') VALUES ' + vals + ';\n';
}

fs.writeFileSync('tmp_zdhc.sql', sql);
console.log('SQL ready');
execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_zdhc.sql'], { stdio: 'inherit', shell: true });
fs.unlinkSync('tmp_zdhc.sql');
console.log('DONE: ' + rows.length + ' rows');
