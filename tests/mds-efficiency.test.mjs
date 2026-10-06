import {currentSid} from "../lib/session-recovery.js";
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
import {scopedCommandKey} from '../lib/collection.js';
const source=readFileSync(new URL('../server.js',import.meta.url),'utf8');
test('System Data reads share a scan cache and queue while CMA data stays scoped',async()=>{
 let requests=0;
 const ctx=vm.createContext({currentSid,appendScanDebug(){},assertNotCancelled(){},operationContext:{getStore(){}},SCAN_CACHEABLE_COMMANDS:new Set(),
 scopedCommandKey,stableJson:JSON.stringify,isExpiredSessionError:()=>false,commandError:e=>({error:e.message}),
 cpRequest:async()=>{requests++;return {value:1};}});
 vm.runInContext(source.slice(source.indexOf('async function tryCommand('),source.indexOf('async function listObjects('))+
 source.slice(source.indexOf('function systemDataReadSession('),source.indexOf('async function tryListSystemDataObjects(')),ctx);
 const root={moraSystemDataCommandCache:new Map()};const queue=()=>{};
 const a=ctx.systemDataReadSession({baseUrl:'https://mds',sid:'a',systemDataSid:'shared',domain:'A',moraRootSession:root,scanApiQueue:queue});
 const b=ctx.systemDataReadSession({baseUrl:'https://mds',sid:'b',systemDataSid:'shared',domain:'B',moraRootSession:root,scanApiQueue:queue});
 await Promise.all([ctx.tryCommand(a,'show-api-settings'),ctx.tryCommand(b,'show-api-settings')]);
 assert.equal(requests,1);assert.equal(a.scanApiQueue,queue);assert.equal(a.domain,'System Data');
 root.moraSystemDataCommandCache=new Map();
 await ctx.tryCommand(ctx.systemDataReadSession({...b,moraRootSession:root}),'show-api-settings');assert.equal(requests,2);
});
test('failed CMA drains in-flight requests before logout or next login',async()=>{
 const events=[];const operation={pending:new Set()};
 const ctx=vm.createContext({currentSid,appendScanDebug(){},Date,Map,Math,Object,Array,Number,HARDENING_GUIDE_URL:'guide',mergeScanSummaries:()=>({}),
 assertNotCancelled(){},log(){},operationContext:{getStore:()=>({operation}),run:(_,fn)=>fn()},
 cpRequest:async(target,command,body)=>{events.push(`${command}:${body.domain||target.sid}`);return command==='login'?{sid:body.domain}:{};},
 scanHardening:async target=>{
 if(target.domain==='A'){
 const sibling=new Promise(resolve=>setTimeout(()=>{events.push('drained:A');operation.pending.delete(sibling);resolve();},10));
 operation.pending.add(sibling);throw Error('collector failed');
 }
 return {commandLog:[],commandResults:{}};
 }});
 vm.runInContext(source.slice(source.indexOf('async function scanMoraHardening('),source.indexOf('async function evaluateSingleHardeningCheck(')),ctx);
 await ctx.scanMoraHardening({id:'root',moraDomains:['A','B'].map(name=>({name,uid:name}))});
 assert.deepEqual(events,['login:A','drained:A','logout:A','login:B','logout:B']);
});
