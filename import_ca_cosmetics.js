const fs = require('fs');
const { execFileSync } = require('child_process');

const raw = fs.readFileSync('C:/BENDA_PROJECT/ROOTS_BY_BENDA/11_INBOX/27.2.2/57da6c9a-41a7-44b0-ab8d-815ff2cd5913.csv', 'utf8');
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
  if (!v || !v.trim() || v.trim() === '""') return 'NULL';
  return "'" + v.trim().replace(/'/g, "''").substring(0, 1000) + "'";
}

const cols = ['cdph_id','product_name','csf','company_name','brand_name','primary_category','sub_category','cas_number','chemical_name','initial_date_reported','most_recent_date_reported','discontinued_date'];

let sql = 'DROP TABLE IF EXISTS california_safe_cosmetics;\n';
sql += 'CREATE TABLE california_safe_cosmetics (id INTEGER PRIMARY KEY AUTOINCREMENT, cdph_id TEXT, product_name TEXT, csf TEXT, company_name TEXT, brand_name TEXT, primary_category TEXT, sub_category TEXT, cas_number TEXT, chemical_name TEXT, initial_date_reported TEXT, most_recent_date_reported TEXT, discontinued_date TEXT);\n';

const rows = lines.slice(1);
let count = 0;
// Process in chunks of SQL files to avoid huge files
const CHUNK = 5000;

for (let c = 0; c < rows.length; c += CHUNK) {
  const chunk = rows.slice(c, c + CHUNK);
  let chunkSql = '';
  
  for (let i = 0; i < chunk.length; i += 50) {
    const batch = chunk.slice(i, i + 50).filter(r => r.trim());
    if (!batch.length) continue;
    const vals = batch.map(r => {
      const f = parseRow(r);
      // Map: skip _id(0), CDPHId(1), ProductName(2), skip CSFId(3), CSF(4), skip CompanyId(5), CompanyName(6), BrandName(7), skip PrimaryCategoryId(8), PrimaryCategory(9), skip SubCategoryId(10), SubCategory(11), skip CasId(12), CasNumber(13), skip ChemicalId(14), ChemicalName(15), InitialDate(16), MostRecent(17), Discontinued(18)
      return '(' + [esc(f[1]),esc(f[2]),esc(f[4]),esc(f[6]),esc(f[7]),esc(f[9]),esc(f[11]),esc(f[13]),esc(f[15]),esc(f[16]),esc(f[17]),esc(f[18])].join(',') + ')';
    }).join(',\n');
    chunkSql += 'INSERT INTO california_safe_cosmetics (' + cols.join(',') + ') VALUES ' + vals + ';\n';
    count += batch.length;
  }
  
  if (c === 0) {
    fs.writeFileSync('tmp_ca.sql', sql + chunkSql);
  } else {
    fs.writeFileSync('tmp_ca.sql', chunkSql);
  }
  
  try {
    execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_ca.sql'], { stdio: 'pipe', shell: true });
    console.log('Chunk ' + (c + CHUNK) + '/' + rows.length + ' done (' + count + ' rows)');
  } catch(e) {
    console.log('Error at chunk ' + c + ', retrying in 15s...');
    const { execSync } = require('child_process');
    execSync('sleep 15');
    try {
      execFileSync('npx', ['wrangler', 'd1', 'execute', 'benda-ingredients', '--remote', '--file=tmp_ca.sql'], { stdio: 'pipe', shell: true });
      console.log('Retry OK: chunk ' + (c + CHUNK));
    } catch(e2) {
      console.log('FAILED chunk ' + c + ': ' + e2.message.substring(0, 100));
    }
  }
}

fs.unlinkSync('tmp_ca.sql');
console.log('DONE: ' + count + ' rows imported');
