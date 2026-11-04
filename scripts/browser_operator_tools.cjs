const {chromium}=require('../release-build/browser/node_modules/playwright-core');
const fs=require('fs');
const assert=require('assert');
(async()=>{
 const out=process.env.WAF_BROWSER_REPORT_ROOT||'research/runs/operator-tools-browser-v1';fs.mkdirSync(out);
 const env=Object.fromEntries(fs.readFileSync('infra/docker/release/.env','utf8').split(/\r?\n/).filter(x=>x.includes('=')).map(x=>[x.slice(0,x.indexOf('=')),x.slice(x.indexOf('=')+1)]));
 const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1500,height:1100}});const errors=[];page.on('pageerror',error=>errors.push(String(error)));const checks={};
 const nav=async name=>{await page.locator('nav').getByRole('button',{name,exact:true}).click();};
 try{
  await page.goto('http://127.0.0.1:'+env.DASHBOARD_PORT);
  await page.getByLabel('Username').fill('dev');await page.getByLabel('Password').fill('dev');await page.getByRole('button',{name:'Continue',exact:true}).click();
  await page.locator('.metric-value').first().waitFor();await page.waitForTimeout(700);
  const before=Number((await page.locator('.metric').filter({has:page.getByText('Requests observed',{exact:true})}).locator('.metric-value').innerText()).replaceAll(',',''));
  await nav('Generator');await page.getByRole('slider').first().focus();await page.keyboard.press('Home');for(let i=0;i<5;i++)await page.keyboard.press('ArrowRight');await page.getByRole('slider').nth(1).focus();await page.keyboard.press('Home');
  await page.getByRole('button',{name:'Send through the gateway',exact:true}).click();
  await page.getByText('Generation complete',{exact:true}).waitFor({timeout:45000});
  await nav('Overview');await page.getByText('Recent console runs',{exact:true}).waitFor();
  await page.waitForFunction(previous=>{const label=[...document.querySelectorAll('.metric')].find(e=>e.querySelector('.metric-label')?.textContent.trim()==='Requests observed');return Number(label?.querySelector('.metric-value')?.textContent.replaceAll(',',''))>previous;},before,{timeout:15000});
  checks.generatorUpdatesOverview=true;await page.screenshot({path:out+'/overview.png',fullPage:true});
  await nav('Redis Cache');await page.locator('tbody tr').first().waitFor();checks.cacheRows=await page.locator('tbody tr').count();assert(checks.cacheRows>0);await page.screenshot({path:out+'/redis.png',fullPage:true});
  await nav('Model Lab');await page.getByRole('button',{name:'Query all HTTP models',exact:true}).click();await page.waitForFunction(()=>document.querySelector('pre')?.textContent.includes('"stage": "deep"'),null,{timeout:45000});checks.allHttpModelsVisible=true;await page.screenshot({path:out+'/model-lab.png',fullPage:true});
  await nav('RL Training');await page.getByRole('button',{name:'Run controlled RL validation',exact:true}).click();await page.waitForFunction(()=>[...document.querySelectorAll('pre')].some(e=>e.textContent.includes('CONTROLLED_SIMULATION')),null,{timeout:30000});checks.rlValidationVisible=true;await page.screenshot({path:out+'/rl-training.png',fullPage:true});
  await nav('Training');await page.getByText('Offline routing training runs',{exact:true}).waitFor();checks.trainingSharesRlRuns=true;
  await nav('Timing');const timingCount=Number(process.env.WAF_TIMING_REQUESTS||120);await page.getByLabel('Requests',{exact:true}).fill(String(timingCount));await page.getByLabel('Concurrency',{exact:true}).fill('4');await page.getByRole('button',{name:'Run timing test',exact:true}).click();await page.getByText('Timing results',{exact:true}).waitFor({timeout:120000});
  const summary=JSON.parse(await page.locator('pre').last().innerText());assert.equal(summary.completed,timingCount);checks.timing=summary;await page.screenshot({path:out+'/timing.png',fullPage:true});
  await nav('Overview');checks.sharedTimingRun=(await page.locator('main').innerText()).includes('Timing');assert(checks.sharedTimingRun);
  await nav('Escalations');await page.getByText('All deferred jobs',{exact:true}).waitFor();await page.locator('tbody tr').first().waitFor({timeout:15000});checks.persistentJobsVisible=await page.locator('tbody tr').count()>0;assert(checks.persistentJobsVisible);await page.locator('tbody tr').filter({hasText:'Completed'}).first().getByText('Inspect result',{exact:true}).click();await page.waitForFunction(()=>[...document.querySelectorAll('details[open] pre')].some(element=>element.textContent.includes('class_scores')));checks.deepProbabilitiesVisible=true;await page.screenshot({path:out+'/escalations.png',fullPage:true});
  checks.javascriptErrors=errors;assert.deepEqual(errors,[]);
  fs.writeFileSync(out+'/results.json',JSON.stringify(checks,null,2));console.log(JSON.stringify(checks,null,2));
 }catch(error){await page.screenshot({path:out+'/failure.png',fullPage:true});fs.writeFileSync(out+'/failure.json',JSON.stringify({error:String(error),checks,errors,body:(await page.locator('body').innerText()).slice(0,12000)},null,2));throw error;}
 finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
