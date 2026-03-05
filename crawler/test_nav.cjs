const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());

(async () => {
    const browser = await puppeteer.launch({
        headless: "new",
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();

    await page.setRequestInterception(true);
    page.on('request', req => {
        const rType = req.resourceType();
        if (['image', 'media', 'font', 'stylesheet', 'other'].includes(rType)) {
            req.abort();
        } else {
            req.continue();
        }
    });

    try {
        console.log("Navigating to https://youtube.com...");
        const response = await page.goto("https://youtube.com", { waitUntil: 'domcontentloaded', timeout: 30000 });
        console.log("Success! Status:", response.status());
    } catch (e) {
        console.error("Timeout/Error:", e.message);
    }
    await browser.close();
})();
