import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, rmSync} from 'node:fs';
import {dirname} from 'node:path';
import {createScanDebug, appendScanDebug, scanDebugSnapshot} from '../lib/scan-debug.js';

test('partial debug is downloadable and written to disk before a request finishes; incremental reads retain failures', () => {
  const journal = createScanDebug({user:'scanner', baseUrl:'https://mds'});
  try {
    appendScanDebug(journal, {requestId:'a', domain:'CMA1', command:'show-objects', status:'started'});
    const partial = scanDebugSnapshot(journal);
    assert.equal(partial.commandLog[0].status, 'started');
    assert.equal(partial.nextOffset, 1);
    assert.equal(JSON.parse(readFileSync(journal.file,'utf8').trim()).domain, 'CMA1');
    appendScanDebug(journal, {requestId:'a', domain:'CMA1', command:'show-objects', status:'failed', statusCode:403, response:{message:'Permission denied'}});
    const delta = scanDebugSnapshot(journal,partial.nextOffset);
    assert.equal(delta.commandLog.length,1);
    assert.equal(delta.commandLog[0].statusCode,403);
    assert.equal(scanDebugSnapshot(journal).commandLog.length,2);
    assert.equal(readFileSync(journal.file,'utf8').trim().split('\n').length,2);
  } finally {rmSync(dirname(journal.file),{recursive:true,force:true});}
});
test('nested credentials and returned SIDs are redacted in memory and on disk', () => {
  const journal = createScanDebug();
  try {
    appendScanDebug(journal,{body:{password:'secret1','api-key':'secret2'},response:{objects:[{sid:'secret3',authorization:'secret4'}]}});
    const output = JSON.stringify(scanDebugSnapshot(journal)) + readFileSync(journal.file,'utf8');
    assert(!/secret[1-4]/.test(output));
    assert(output.includes('[redacted]'));
  } finally {rmSync(dirname(journal.file),{recursive:true,force:true});}
});
test('disk failure preserves downloadable memory log and reports persistence failure', () => {
  const journal = {commandLog:[],file:'/nonexistent/cp-debug/scan.jsonl'};
  appendScanDebug(journal,{command:'scan',status:'failed'});
  assert.equal(scanDebugSnapshot(journal).commandLog.length,1);
  assert(journal.writeError);
});
