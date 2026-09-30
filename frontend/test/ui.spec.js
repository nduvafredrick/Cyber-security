const {test,expect}=require('@playwright/test');

test('Sentinel console signs in and renders the SOC dashboard',async({page})=>{
  await page.goto('http://127.0.0.1:3001/');
  await expect(page.getByRole('heading',{name:'Sentinel'})).toBeVisible();
  await page.getByPlaceholder('Username').fill('admin');
  await page.getByPlaceholder('Password').fill('ci-password');
  await page.getByRole('button',{name:'Sign in to console'}).click();
  await expect(page.getByRole('heading',{name:'Overview'})).toBeVisible();
  await expect(page.getByText('SECURITY OPERATIONS CENTER')).toBeVisible();
  await expect(page.getByRole('button',{name:'Events'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Alerts'})).toBeVisible();
});

test('Events view supports search and severity filtering',async({page})=>{
  await page.goto('http://127.0.0.1:3001/');
  await page.getByPlaceholder('Username').fill('admin');
  await page.getByPlaceholder('Password').fill('ci-password');
  await page.getByRole('button',{name:'Sign in to console'}).click();
  await page.getByRole('button',{name:'Events'}).click();
  await expect(page.getByRole('heading',{name:'Security Events'})).toBeVisible();
  await page.getByLabel('Search events').fill('browser-test');
  await page.getByLabel('Filter severity').selectOption('HIGH');
  await expect(page.getByLabel('Search events')).toHaveValue('browser-test');
  await expect(page.getByLabel('Filter severity')).toHaveValue('HIGH');
});
