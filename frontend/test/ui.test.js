const test=require('node:test');
const assert=require('node:assert/strict');
const {chromium}=require('playwright');

let browser;
test.before(async()=>{browser=await chromium.launch({headless:true})});
test.after(async()=>{await browser?.close()});

async function login(page){
  await page.goto('http://127.0.0.1:3002/');
  await page.getByPlaceholder('Username').fill('admin');
  await page.getByPlaceholder('Password').fill('ci-password');
  await page.getByRole('button',{name:'Sign in to console'}).click();
}

test('Sentinel console signs in and renders the SOC dashboard',async()=>{
  const page=await browser.newPage();
  await login(page);
  assert.equal(await page.getByRole('heading',{name:'Overview'}).isVisible(),true);
  assert.equal(await page.getByText('SECURITY OPERATIONS CENTER').isVisible(),true);
  assert.equal(await page.getByRole('button',{name:'Events'}).isVisible(),true);
  assert.equal(await page.getByRole('button',{name:'Alerts'}).isVisible(),true);
  await page.close();
});

test('Events view supports search and severity filtering',async()=>{
  const page=await browser.newPage();
  await login(page);
  await page.getByRole('button',{name:'Events'}).click();
  assert.equal(await page.getByRole('heading',{name:'Security Events'}).isVisible(),true);
  await page.getByLabel('Search events').fill('browser-test');
  await page.getByLabel('Filter severity').selectOption('HIGH');
  assert.equal(await page.getByLabel('Search events').inputValue(),'browser-test');
  assert.equal(await page.getByLabel('Filter severity').inputValue(),'HIGH');
  await page.close();
});
