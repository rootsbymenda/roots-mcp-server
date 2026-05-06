const fs = require('fs');
const { execFileSync } = require('child_process');
const raw = fs.readFileSync('C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/epa_list_of_lists_april2025.csv', 'utf8');
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

const cols = ['chemical_name','cas_number','comptox_id','epcra_302_ehs','epcra_302_ehs_tpq_lbs','epcra_304_ehs_rq_lbs','cercla_rq_lbs','epcra_313_tri','caa_112r_tq_lbs','cwa_311_hs','cwa_311_hs_tq_lbs','rcra_code'];

let sql = 'DROP TABLE IF EXISTS epa_list_of_lists;\n';
sql += 'CREATE TABLE epa_list_of_lists (id INTEGER PRIMARY KEY AUTOINCREMENT, ' + cols.map(c => c + ' TEXT').join(', ') + ');\n';

const rows = lines.slice(1);
for (let i = 0; i < rows.length; i += 100) {
  const batch = rows.slice(i, i + 100).filter(r => r.trim());
  if (!batch.length) continue;
  const vals = batch.map(r => {
    const c = parseRow(r);
    return '(' + cols.map((_, j) => esc(c[j] || '')).join(',') + ')';
  }).join(',\n');
  sql += 'INSERT INTO epa_list_of_lists (' + cols.join(',') + ') VALUES ' + vals + ';\n';
}

fs.writeFileSync('tmp_epa_lol.sql', sql);
console.log('SQL ready: ' + rows.length + ' rows');
execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_epa_lol.sql'], { stdio: 'inherit', shell: true });
fs.unlinkSync('tmp_epa_lol.sql');
console.log('DONE');
