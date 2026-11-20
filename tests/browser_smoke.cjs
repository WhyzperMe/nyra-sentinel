const assert = require('node:assert/strict');
const { chromium } = require('playwright');

async function main() {
  const token = process.env.NYRA_TEST_TOKEN;
  assert(token, 'Set NYRA_TEST_TOKEN to the isolated test stack operator credential');
  const browser = await chromium.launch({ executablePath: process.env.NYRA_TEST_CHROMIUM });
  try {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    page.setDefaultTimeout(8000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const response = await page.goto(`${process.env.NYRA_TEST_URL || 'http://127.0.0.1:8765'}/ui`);
    assert.match(response.headers()['content-security-policy'], /script-src 'self'/);
    await page.getByLabel('Operator API token').fill('x'.repeat(64));
    await page.getByRole('button', { name: 'Connect' }).click();
    await page.getByRole('status').filter({ hasText: 'Authentication failed' }).waitFor();
    await page.getByLabel('Operator API token').fill(token);
    await page.getByLabel('Operator API token').press('Enter');
    await page.locator('#workspace').waitFor();
    await page.waitForFunction(() => document.querySelector('#total-events').textContent !== '—');

    const payload = '<img src=x onerror="window.nyraInjected=true">';
    await page.route('**/api/v1/security-events?*', route => route.fulfill({
      json: { events: [{ category: payload, source_ip: '192.0.2.4' }], next_cursor: null },
    }));
    await page.getByRole('button', { name: 'Telemetry' }).click();
    await page.getByRole('cell', { name: payload, exact: true }).waitFor();
    assert.equal(await page.locator('#events-table img').count(), 0);
    assert.equal(await page.evaluate(() => window.nyraInjected), undefined);
    assert.equal(await page.getByRole('button', { name: 'Telemetry' }).getAttribute('aria-current'), 'page');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    await page.reload();
    await page.getByRole('button', { name: 'Connect' }).waitFor();
    assert.deepEqual(errors, []);
    console.log('PASS Chromium login, dashboard, mobile layout, telemetry rendering and token isolation');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
