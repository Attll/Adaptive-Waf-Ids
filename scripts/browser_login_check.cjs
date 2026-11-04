// Uses the local optional browser QA dependency; never prints credentials.
const { chromium } = require('../release-build/browser/node_modules/playwright-core');
const fs = require('fs');
(async () => {
  const env = Object.fromEntries(fs.readFileSync('infra/docker/release/.env', 'utf8').split(/\r?\n/)
    .filter(line => line.includes('=')).map(line => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]));
  const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(String(error)));
    await page.goto('http://127.0.0.1:' + env.DASHBOARD_PORT);
    const misleadingButtonRemoved = await page.getByRole('button', { name: 'Use local credentials' }).count() === 0;
    const guidanceRemoved = await page.getByText('Use the administrator credentials configured for this deployment.', { exact: true }).count() === 0;
    await page.getByLabel('Username').fill(process.env.WAF_BROWSER_USERNAME || env.ADMIN_USERNAME);
    await page.getByLabel('Password').fill(process.env.WAF_BROWSER_PASSWORD || env.ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await page.locator('nav').getByRole('button', { name: 'Overview', exact: true }).waitFor();
    const report = { authenticatedOverview: true, misleadingButtonRemoved, guidanceRemoved, javascriptErrors: errors };
    fs.writeFileSync(process.env.WAF_BROWSER_REPORT || 'research/runs/login-browser-v1.json', JSON.stringify(report, null, 2), { flag: 'wx' });
    console.log(JSON.stringify(report));
    if (!misleadingButtonRemoved || !guidanceRemoved || errors.length) process.exitCode = 1;
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
