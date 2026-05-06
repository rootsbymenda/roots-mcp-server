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
  return "'" + v.trim().replace(/'/g, "''").substring(0, 1000) + "'";
}

function importCSV(file, table, label) {
  console.log('\n=== ' + label + ' ===');
  const raw = fs.readFileSync(file, 'utf8');
  const lines = raw.replace(/^\uFEFF/, '').split('\n').filter(l => l.trim());
  const cols = parseRow(lines[0]).map(c => c.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/_+/g, '_'));
  const rows = lines.slice(1);
  console.log('Columns: ' + cols.length + ', Rows: ' + rows.length);

  const CHUNK = 5000;
  let count = 0;

  for (let c = 0; c < rows.length; c += CHUNK) {
    const chunk = rows.slice(c, c + CHUNK);
    let sql = '';

    if (c === 0) {
      sql += 'DROP TABLE IF EXISTS ' + table + ';\n';
      sql += 'CREATE TABLE ' + table + ' (id INTEGER PRIMARY KEY AUTOINCREMENT, ' + cols.map(col => col + ' TEXT').join(', ') + ');\n';
    }

    for (let i = 0; i < chunk.length; i += 50) {
      const batch = chunk.slice(i, i + 50).filter(r => r.trim());
      if (!batch.length) continue;
      const vals = batch.map(r => {
        const f = parseRow(r);
        return '(' + cols.map((_, j) => esc(f[j] || '')).join(',') + ')';
      }).join(',\n');
      sql += 'INSERT INTO ' + table + ' (' + cols.join(',') + ') VALUES ' + vals + ';\n';
      count += batch.length;
    }

    fs.writeFileSync('tmp_batch.sql', sql);
    let retries = 0;
    while (retries < 3) {
      try {
        execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_batch.sql'], { stdio: 'pipe', shell: true });
        break;
      } catch(e) {
        retries++;
        console.log('  Retry ' + retries + '/3...');
        execSync('sleep 15');
      }
    }
    if ((c + CHUNK) % 10000 === 0 || c + CHUNK >= rows.length) {
      console.log('  ' + count + '/' + rows.length);
    }
  }
  try { fs.unlinkSync('tmp_batch.sql'); } catch(e) {}
  console.log('DONE: ' + count + ' rows');
  return count;
}

const BASE = 'C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/';
let total = 0;

total += importCSV(BASE + 'incb_green_list_29th_edition.csv', 'incb_green_list', 'INCB Green List (144)');
total += importCSV(BASE + 'oeko_tex_standard_100_limit_values.csv', 'oeko_tex_limits', 'OEKO-TEX Standard 100 (195)');
total += importCSV(BASE + 'codex_vetdrugs_mrl_complete.csv', 'codex_vetdrug_mrls', 'Codex Vet Drug MRLs (711)');
total += importCSV(BASE + 'epa_antimicrobial_products.csv', 'epa_antimicrobial_products', 'EPA Antimicrobial Products (163K)');

console.log('\n=== ALL DONE === Total: ' + total);
