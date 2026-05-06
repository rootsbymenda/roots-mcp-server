const fs = require('fs');
const { execFileSync, execSync } = require('child_process');

const raw = fs.readFileSync('C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/eudamed_devices.csv', 'utf8');
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
  return "'" + v.trim().replace(/'/g, "''").substring(0, 1000) + "'";
}

const cols = parseRow(lines[0]).map(c => c.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/_+/g, '_'));
const rows = lines.slice(1);
console.log('Columns: ' + cols.length + ', Rows: ' + rows.length);

const CHUNK = 5000;
let count = 0;

for (let c = 0; c < rows.length; c += CHUNK) {
  const chunk = rows.slice(c, c + CHUNK);
  let sql = '';

  if (c === 0) {
    sql += 'DROP TABLE IF EXISTS eudamed_devices;\n';
    sql += 'CREATE TABLE eudamed_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, ' + cols.map(col => col + ' TEXT').join(', ') + ');\n';
  }

  for (let i = 0; i < chunk.length; i += 50) {
    const batch = chunk.slice(i, i + 50).filter(r => r.trim());
    if (!batch.length) continue;
    const vals = batch.map(r => {
      const f = parseRow(r);
      return '(' + cols.map((_, j) => esc(f[j] || '')).join(',') + ')';
    }).join(',\n');
    sql += 'INSERT INTO eudamed_devices (' + cols.join(',') + ') VALUES ' + vals + ';\n';
    count += batch.length;
  }

  fs.writeFileSync('tmp_eudamed.sql', sql);
  let retries = 0;
  while (retries < 3) {
    try {
      execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_eudamed.sql'], { stdio: 'pipe', shell: true });
      break;
    } catch(e) {
      retries++;
      console.log('Retry ' + retries + '/3...');
      execSync('sleep 15');
    }
  }
  console.log(count + '/' + rows.length);
}

try { fs.unlinkSync('tmp_eudamed.sql'); } catch(e) {}
console.log('DONE: ' + count + ' rows');
