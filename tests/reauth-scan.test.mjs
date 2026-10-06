import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync,existsSync} from 'node:fs';
import {createScanDebug,appendScanDebug,scanDebugSnapshot,removeScanDebug} from '../lib/scan-debug.js';
const frontend=readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
const backend=readFileSync(new URL('../server.js',import.meta.url),'utf8');
test('reauthentication does not replay an interrupted scan',async()=>{
 let calls=0,reconnected=0;
 const ctx=vm.createContext({sessionId:'fresh',browserDebugId:'debug',
 fetch:async()=>{calls++;return {ok:false,headers:{get:()=> 'application/json'},json:async()=>({error:'Wrong session id',sessionExpired:true})};},
 isSessionExpiredError:()=>true,collectLiveDebug:async()=>{},promptForReauthentication:async()=>{reconnected++;}});
 vm.runInContext(frontend.slice(frontend.indexOf('async function api('),frontend.indexOf('function isSessionExpiredError(')),ctx);
 await assert.rejects(ctx.api('/api/scan',{sessionId:'expired'}),/cannot resume.*debug log is preserved/);
 assert.equal(calls,1);assert.equal(reconnected,1);
});
test('permission denied is not classified as session expiry on either side',()=>{
 const server=vm.runInNewContext(backend.slice(backend.indexOf('function isExpiredSessionError('),backend.indexOf('async function tryCommand('))+';isExpiredSessionError');

 assert.equal(server({message:'Permission denied',statusCode:403}),false);
 assert.equal(server({message:'Wrong session id',statusCode:403}),true);
});
test('full scan journal exceeds old truncation limit and logout cleanup removes disk file',()=>{
 const journal=createScanDebug();
 for(let i=0;i<10005;i++) appendScanDebug(journal,{command:'check',status:'ok',sequence:i});
 const snapshot=scanDebugSnapshot(journal);
 assert.equal(snapshot.commandLog.length,10005);
 assert.equal(snapshot.commandLog[0].sequence,0);
 const file=journal.file;removeScanDebug(journal);assert.equal(existsSync(file),false);
});
