const {chromium}=require('../release-build/browser/node_modules/playwright-core');
const fs=require('fs');
(async()=>{
 const env=Object.fromEntries(fs.readFileSync('infra/docker/release/.env','utf8').split(/\r?\n/).filter(x=>x.includes('=')).map(x=>[x.slice(0,x.indexOf('=')),x.slice(x.indexOf('=')+1)]));
 const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(String(e)));
 await page.goto('http://127.0.0.1:'+env.DASHBOARD_PORT);await page.getByLabel('Username').fill(env.ADMIN_USERNAME);await page.getByLabel('Password').fill(env.ADMIN_PASSWORD);await page.getByRole('button',{name:'Continue',exact:true}).click();
 await page.getByText('Overview',{exact:true}).first().waitFor(); await page.request.get('http://127.0.0.1:'+env.GATEWAY_PORT+'/backend/health'); await page.waitForTimeout(1000);
 const pages=[]; const count=await page.locator('nav button').count(); for(let i=0;i<count;i++){const name=await page.locator('nav button').nth(i).innerText(); await page.locator('nav button').nth(i).click(); await page.locator('.breadcrumb strong').waitFor(); await page.waitForTimeout(500); if(name==='Research')await page.getByText('Live inference telemetry',{exact:true}).waitFor(); pages.push({name,heading:await page.locator('.breadcrumb strong').innerText(),text:(await page.locator('main').innerText()).slice(0,700)}); if(/Models|Research|Infrastructure/.test(name)) await page.screenshot({path:'research/runs/docker-browser-'+i+'-v55.png',fullPage:true});} console.log(pages.map(x=>x.name));
 await page.screenshot({path:'research/runs/docker-browser-last-v55.png',fullPage:true});
 fs.writeFileSync('research/runs/docker-browser-v55.json',JSON.stringify({title:await page.title(),errors,pages,stream:await page.locator('.sidebar-footer').innerText(),body:(await page.locator('body').innerText()).slice(0,5000)},null,2));
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
