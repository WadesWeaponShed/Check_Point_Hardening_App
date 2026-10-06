import {chromium} from 'playwright';
import assert from 'node:assert/strict';
const browser=await chromium.launch({headless:true,channel:'chrome'});
const check={id:'mgmt.test',title:'Completed CMA check',category:'Policy and Access',status:'needs-review',severity:'medium',recommendation:'Review settings',evidence:'Retained evidence',details:'Collected successfully',commands:[]};
const scan={checks:[check],summary:{'needs-review':1},gateways:[],managementObjectName:'Donut',commandLog:[],commandResults:{}};
const result={moraMode:true,scannedAt:new Date().toISOString(),domains:[{name:'Failed CMA',uid:'failed',scan:null,error:'Permission denied'},{name:'Katia',uid:'katia',scan,error:''}],checks:[],commandLog:[],commandResults:{}};
try{
for(const [scenario,width] of [['mixed',1440],['cancelled',390],['lost-status',1440]]){
 const page=await browser.newPage({viewport:{width,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));let calls=0;
 const fixture=scenario==='mixed'?result:{...result,partial:true,totalDomains:3};
 await page.route('**/api/**',async route=>{
 const path=new URL(route.request().url()).pathname;let data={ok:true};
 if(path==='/api/health')data={ok:true};
 if(path==='/api/login')data={sessionId:'test',baseUrl:'https://mds',user:'test',moraMode:true,mdsMode:true,domains:[{name:'Katia',available:true}]};
 if(path==='/api/scan')data={scanId:'job',state:'running'};
 if(path==='/api/scan-status'){
  calls++;
  if(scenario==='lost-status'&&calls>1){await route.abort('failed');return;}
  data={state:scenario==='lost-status'?'running':scenario==='cancelled'?'cancelled':'complete',result:fixture,completedDomains:2,progress:{complete:scenario!=='lost-status'},failure:scenario==='cancelled'?{message:'Scan cancelled'}:null};
 }
 if(path==='/api/scan-checkpoint')data={result:fixture};
 if(path==='/api/scan-debug')data={debug:null};
 await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)});
 });
 await page.goto(process.env.APP_URL || 'http://127.0.0.1:3001');await page.waitForSelector('#downloadCheckpointButton',{state:'attached'});
 await page.locator('#host').fill('mds');await page.locator('#username').fill('test');await page.locator('#password').fill('test');await page.locator('#loginForm').evaluate(form=>form.requestSubmit());
 await page.locator('#scanButton').waitFor({state:'visible'});await page.locator('#scanButton').click();
 const domain=page.getByRole('combobox',{name:'Domain',exact:true});await domain.waitFor();
 await page.waitForFunction(()=>!document.querySelector('#scanButton').classList.contains('is-scanning'));
 assert.equal(await domain.inputValue(),'katia');assert((await domain.locator('option').allTextContents()).some(t=>t.includes('scan failed')));
 assert((await page.locator('#scanStatus').innerText()).includes('Domains scanned'));
 if(scenario!=='mixed'){assert((await page.locator('#scanStatus').innerText()).includes('Domains pending'));assert((await page.locator('#scanStatus').innerText()).includes('remain available'));}
 await page.locator('#categoryViewButton').click();
 await page.locator('.wb-nav-list summary').first().click();
 await page.getByRole('button',{name:/Completed CMA check/}).click();
 assert((await page.locator('#selectedCheckEvidence').innerText()).includes('Retained evidence'));
 assert(!((await page.locator("body").innerText()).includes("[object Object]")));
 assert.deepEqual(errors,[]);
 await page.screenshot({path:`/tmp/completed-cma-${scenario}.png`,fullPage:true});
 console.log(`${scenario}: successful CMA selected, failed CMA labeled, retained evidence navigable.`);await page.close();
}
}finally{await browser.close();}
