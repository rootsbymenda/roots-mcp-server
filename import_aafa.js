const fs = require('fs');
const { execFileSync } = require('child_process');
const raw = fs.readFileSync('C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/AAFA_RSL_V26.csv', 'utf8');
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
let sql = 'DROP TABLE IF EXISTS aafa_rsl;\n';
sql += 'CREATE TABLE aafa_rsl (id INTEGER PRIMARY KEY AUTOINCREMENT, ' + cols.map(c => c + ' TEXT').join(', ') + ');\n';

const rows = lines.slice(1);
for (let i = 0; i < rows.length; i += 50) {
  const batch = rows.slice(i, i + 50).filter(r => r.trim());
  if (!batch.length) continue;
  const vals = batch.map(r => {
    const f = parseRow(r);
    return '(' + cols.map((_, j) => esc(f[j] || '')).join(',') + ')';
  }).join(',\n');
  sql += 'INSERT INTO aafa_rsl (' + cols.join(',') + ') VALUES ' + vals + ';\n';
}

fs.writeFileSync('tmp_aafa.sql', sql);
console.log('SQL ready: ' + rows.length + ' rows');
execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_aafa.sql'], { stdio: 'inherit', shell: true });
fs.unlinkSync('tmp_aafa.sql');
console.log('DONE: ' + rows.length + ' rows');
