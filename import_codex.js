const fs = require('fs');
const { execFileSync } = require('child_process');

const raw = fs.readFileSync('C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/codex_alimentarius_pesticide_mrls.csv', 'utf8');
const lines = raw.split('\n').filter(l => l.trim());

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

const cols = parseRow(lines[0]).map(c => c.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_'));
const colDef = cols.map(c => c + ' TEXT').join(', ');

let sql = 'DROP TABLE IF EXISTS codex_pesticide_mrls;\n';
sql += 'CREATE TABLE codex_pesticide_mrls (id INTEGER PRIMARY KEY AUTOINCREMENT, ' + colDef + ');\n';

const rows = lines.slice(1);
for (let i = 0; i < rows.length; i += 50) {
  const batch = rows.slice(i, i + 50).filter(r => r.trim());
  if (!batch.length) continue;
  const vals = batch.map(r => {
    const c = parseRow(r);
    return '(' + cols.map((_, j) => esc(c[j] || '')).join(',') + ')';
  }).join(',\n');
  sql += 'INSERT INTO codex_pesticide_mrls (' + cols.join(',') + ') VALUES ' + vals + ';\n';
}

fs.writeFileSync('tmp_codex.sql', sql);
console.log('SQL ready: ' + rows.length + ' rows');
execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_codex.sql'], { stdio: 'inherit', shell: true });
fs.unlinkSync('tmp_codex.sql');
console.log('DONE');
