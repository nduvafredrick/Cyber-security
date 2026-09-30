const test=require('node:test');
const assert=require('node:assert/strict');
const {chromium}=require('playwright');

let browser;
test.before(async()=>{browser=await chromium.launch({headless:true})});
test.after(async()=>{await browser?.close()});

async function login(page){
  const errors=[];
  page.on('console',msg=>{if(msg.type()==='error')errors.push('console: '+msg.text())});
  page.on('pageerror',err=>errors.push('pageerror: '+err.message));
  const response=await page.goto('http://127.0.0.1:3002/',{waitUntil:'domcontentloaded'});
  assert.ok(response,'UI page did not return a response');
  assert.equal(response.status(),200);
  await page.locator('#root > *').first().waitFor({timeout:10000}).catch(()=>{});
  const rootChildren=await page.locator('#root').locator('> *').count();
  if(rootChildren===0){
    const body=await page.locator('body').innerText().catch(()=> '');
    throw new Error('React app did not mount. '+errors.join(' | ')+' BODY='+body.slice(0,500));
  }
  await page.getByPlaceholder('Username').fill('admin',{timeout:5000}).catch(async err=>{
    const body=await page.locator('body').innerText().catch(()=> '');
    throw new Error('Login form missing. '+errors.join(' | ')+' BODY='+body.slice(0,500)+' URL='+page.url());
  });
  await page.getByPlaceholder('Password').fill('ci-password');
  await page.getByRole('button',{name:'Sign in to console'}).click();
}

test('Sentinel console signs in and renders the SOC dashboard',async()=>{
  const page=await browser.newPage();
  await login(page);
  await page.getByRole('heading',{name:'Overview'}).waitFor({state:'visible',timeout:10000});
  await page.getByText('SECURITY OPERATIONS CENTER').waitFor({state:'visible',timeout:10000});
  await page.getByRole('button',{name:'Events'}).waitFor({state:'visible',timeout:10000});
  await page.getByRole('button',{name:'Alerts'}).waitFor({state:'visible',timeout:10000});
  await page.close();
});

test('Authenticated users visiting onboarding see the onboarding flow',async()=>{
  const page=await browser.newPage();
  await login(page);
  await page.goto('http://127.0.0.1:3002/onboarding',{waitUntil:'domcontentloaded'});
  await page.getByRole('heading',{name:'Create your Sentinel workspace'}).waitFor({state:'visible',timeout:10000});
  await page.close();
});

test('Events view supports search and severity filtering',async()=>{
  const page=await browser.newPage();
  await login(page);
  await page.getByRole('button',{name:'Events'}).click();
  await page.getByRole('heading',{name:'Security Events'}).waitFor({state:'visible',timeout:10000});
  await page.getByLabel('Search events').fill('browser-test');
  await page.getByLabel('Filter severity').selectOption('HIGH');
  assert.equal(await page.getByLabel('Search events').inputValue(),'browser-test');
  assert.equal(await page.getByLabel('Filter severity').inputValue(),'HIGH');
  await page.close();
});

test('Company onboarding provisions a workspace and verifies its first event',async()=>{
  const page=await browser.newPage();
  await page.goto('http://127.0.0.1:3002/onboarding',{waitUntil:'domcontentloaded'});
  await page.getByRole('heading',{name:'Create your Sentinel workspace'}).waitFor({state:'visible',timeout:10000});
  await page.getByLabel('Company name').fill('Browser Test '+Date.now());
  await page.getByRole('button',{name:'Continue to administrator'}).click();
  const email='browser-'+Date.now()+'@example.com';
  await page.getByLabel('Work email').fill(email);
  await page.getByRole('textbox',{name:'Password',exact:true}).fill('browser-onboarding-password');
  await page.getByLabel('Confirm password').fill('browser-onboarding-password');
  await page.getByRole('button',{name:'Continue to connector'}).click();
  await page.getByLabel('Connector name').fill('Browser Test Connector');
  await page.getByLabel('Environment').selectOption('Staging');
  await page.getByRole('button',{name:'Create workspace'}).click();
  await page.getByText('WORKSPACE CREATED').waitFor({state:'visible',timeout:10000});
  await page.getByRole('button',{name:'Reveal key'}).click();
  await page.getByRole('button',{name:'Send a test event'}).click();
  await page.getByRole('button',{name:'Test event received'}).waitFor({state:'visible',timeout:10000});
  await page.getByRole('button',{name:'Open Sentinel'}).click();
  await page.getByRole('heading',{name:'Overview'}).waitFor({state:'visible',timeout:10000});
  await page.close();
});
