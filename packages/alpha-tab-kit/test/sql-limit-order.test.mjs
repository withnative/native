import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { lintSql, lintSqlLimitOrder } from '../src/index.mjs';
const oldReads=JSON.parse(readFileSync(new URL('vectors/notion-0.4.1-limit-order.json',import.meta.url),'utf8'));
for(const {key,sql} of oldReads){
 test(`embedded ${key}: all levels are checked; ad-hoc top-level repair stays accepted`,()=>{
  const found=lintSqlLimitOrder(sql,{profile:'query_sql',where:key});
  assert.equal(found.length,key==='notion.database_count'?0:key==='notion.ancestors'?2:3);
  assert.ok(found.every(f=>f.rule==='sql.limit-order'&&f.where.startsWith(key)));
 });
}
for(const sql of [
 'SELECT (SELECT value FROM facet_values ORDER BY id LIMIT 1) FROM records ORDER BY id LIMIT 1',
 'WITH s AS (SELECT id FROM records ORDER BY id LIMIT 1) SELECT id FROM s ORDER BY id LIMIT 1',
 'WITH RECURSIVE walk(id) AS (SELECT id FROM records UNION ALL SELECT id FROM walk ORDER BY 1 LIMIT 257) SELECT id FROM walk ORDER BY id LIMIT 257',
 "SELECT 'LIMIT', \"LIMIT\" FROM records /* LIMIT 1 */ ORDER BY id LIMIT 1 -- LIMIT 1",
 'SELECT (SELECT id FROM records ORDER BY id LIMIT 1) FROM records',
])test(`ordered/literal/comment control: ${sql}`,()=>assert.deepEqual(lintSqlLimitOrder(sql),[]));
for(const sql of [
 'SELECT (SELECT id FROM records LIMIT 1) FROM records ORDER BY id LIMIT 1',
 'SELECT (SELECT id FROM records ORDER BY id LIMIT 1), (SELECT id FROM records LIMIT 1)',
 'WITH a AS (SELECT id FROM records ORDER BY id LIMIT 1), b AS (SELECT id FROM records LIMIT 1) SELECT * FROM a',
 'WITH RECURSIVE a(id) AS (SELECT id FROM records UNION ALL SELECT id FROM a LIMIT 5) SELECT * FROM a ORDER BY id LIMIT 5',
 'SELECT row_number() OVER (ORDER BY id) FROM records LIMIT 1',
])test(`orders cannot leak between levels: ${sql}`,()=>{
 assert.equal(lintSqlLimitOrder(sql).length,1);
 assert.equal(lintSql(sql).filter(f=>f.rule==='sql.limit-order').length,1);
});
test('saved declarations stay strict; query_sql repairs only the top-level LIMIT',()=>{
 const sql='SELECT count(*) AS total FROM records LIMIT 1';
 assert.equal(lintSqlLimitOrder(sql).length,1);
 assert.equal(lintSql(sql).filter(f=>f.rule==='sql.limit-order').length,1);
 assert.deepEqual(lintSqlLimitOrder(sql,{profile:'query_sql'}),[]);
 assert.equal(lintSqlLimitOrder('WITH c AS (SELECT id FROM records LIMIT 1) SELECT * FROM c LIMIT 1',{profile:'query_sql'}).length,1);
});
