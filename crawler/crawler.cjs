const { Cluster } = require('puppeteer-cluster');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const iconv = require('iconv-lite');

puppeteer.use(StealthPlugin());

const OUTPUT_ROOT = './collected_scripts';
if (!fs.existsSync(OUTPUT_ROOT)) fs.mkdirSync(OUTPUT_ROOT);
const FAIL_ROOT = './fail_scripts';
if (!fs.existsSync(FAIL_ROOT)) fs.mkdirSync(FAIL_ROOT);

let crawlerStats = { success: 0, fail: 0 };

(async () => {
    const startTime = new Date();
    try {
        const listFile = process.argv[2];
        if (!listFile) {
            console.log("Usage: node crawler.cjs <url_list.txt>");
            process.exit(1);
        }

        let urls = [];
        try {
            urls = fs.readFileSync(listFile, 'utf-8')
                .split('\n')
                .map(l => l.trim())
                .filter(l => l && !l.startsWith('#'))
                .map(l => {
                    const parts = l.split(',');
                    return parts.length > 1 ? parts[1].trim() : l;
                });
        } catch (e) {
            console.error(`Error reading file: ${e.message}`);
            process.exit(1);
        }

        const cluster = await Cluster.launch({
            concurrency: Cluster.CONCURRENCY_BROWSER,
            maxConcurrency: 1,
            monitor: true,
            timeout: 240000,
            puppeteerOptions: {
                headless: "new",
                protocolTimeout: 600000,
                pipe: true,
                ignoreHTTPSErrors: true,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--ignore-certificate-errors',
                    '--ignore-certificate-errors-spki-list',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process'
                ]
            }
        });

        cluster.on('taskerror', (err, data) => {
            console.error(`\n    [FAILED] ${data}: ${err.message}`);
        });

        await cluster.task(async ({ page, data: targetUrl }) => {
            console.log(`\n>>> Processing: ${targetUrl}`);

            if (!/^https?:\/\//i.test(targetUrl)) {
                targetUrl = 'https://' + targetUrl;
            }

            let hostname;
            try { hostname = new URL(targetUrl).hostname; } catch (e) { return; }
            let scriptCollectedCount = 0;

            const siteDir = path.join(OUTPUT_ROOT, hostname);
            if (!fs.existsSync(siteDir)) fs.mkdirSync(siteDir, { recursive: true });

            const wholePagePath = path.join(siteDir, 'wholepage.js');
            if (fs.existsSync(wholePagePath)) fs.unlinkSync(wholePagePath);
            fs.writeFileSync(wholePagePath, '\uFEFF');

            const interceptedUrls = new Set();

            const { Deobfuscator } = await import('restringer');
            const babel = require('@babel/core');
            const beautify = require('js-beautify').js;

            await page.setRequestInterception(true);
            page.on('request', req => {
                const rType = req.resourceType();
                const reqUrl = req.url();

                if (reqUrl.startsWith('http')) {
                    interceptedUrls.add(reqUrl);
                }

                if (['image', 'media', 'font'].includes(rType)) {
                    req.abort();
                } else {
                    req.continue();
                }
            });

            page.on('response', async (response) => {
                try {
                    const rUrl = response.url();
                    const headers = response.headers();
                    const contentType = (headers['content-type'] || '').toLowerCase();

                    if (contentType.includes('javascript') || rUrl.endsWith('.js')) {
                        let buffer;
                        try { buffer = await response.buffer(); } catch (e) { return; }
                        if (!buffer || buffer.length === 0) return;

                        let charset = 'utf-8';
                        if (contentType.includes('euc-kr') || contentType.includes('ks_c_5601')) charset = 'euc-kr';
                        else if (contentType.includes('cp949')) charset = 'cp949';

                        let code = iconv.decode(buffer, charset);

                        if (code.includes('') && charset === 'utf-8') {
                            const retryCode = iconv.decode(buffer, 'euc-kr');
                            if (!retryCode.includes('')) code = retryCode;
                        }

                        if (code.includes('ì') || code.includes('í') || code.includes('ï')) {
                            try {
                                const repaired = Buffer.from(code, 'binary').toString('utf-8');
                                if (repaired.includes('이') || repaired.includes('실') || repaired.includes('var')) {
                                    code = repaired;
                                }
                            } catch (e) { }
                        }

                        if (!code || code.trim().length === 0) return;

                        if (code.length < 250000) {
                            try {
                                const deobfuscator = new Deobfuscator(code, { unsafe: true, normalize: true, simplify: true });
                                const cleanCode = deobfuscator.deobfuscate();
                                if (cleanCode !== code) code = cleanCode;
                            } catch (e) { }

                            try {
                                code = code.replace(/import\.meta/g, '({url:"http://mock-url.com"})');
                                const res = babel.transformSync(code, {
                                    presets: [['@babel/preset-env', { targets: { ie: "11" }, modules: "commonjs", useBuiltIns: false }]],
                                    plugins: [
                                        ["@babel/plugin-transform-class-properties", { "loose": true }],
                                        ["@babel/plugin-transform-private-methods", { "loose": true }],
                                        ["@babel/plugin-transform-private-property-in-object", { "loose": true }],
                                        ["@babel/plugin-transform-async-generator-functions"]
                                    ],
                                    sourceType: "unambiguous",
                                    compact: false,
                                    comments: true,
                                    generatorOpts: { jsescOption: { minimal: true } }
                                });
                                code = res.code;
                            } catch (e) { }

                            try {
                                const formatted = beautify(code, {
                                    indent_size: 2,
                                    space_in_empty_paren: true,
                                    unescape_strings: false
                                });
                                if (formatted && formatted.length > 0) code = formatted;
                            } catch (e) { }
                        }

                        if (code) {
                            code = code.replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
                        }

                        const fileName = path.basename(new URL(rUrl).pathname) || 'script.js';
                        const safeName = fileName.replace(/[^a-z0-9.]/gi, '_') + '_' + Date.now() + '.js';
                        fs.writeFileSync(path.join(siteDir, safeName), code);

                        const fileHeader = `\n\n// ==========================================\n// [FILE] Source: ${rUrl}\n// ==========================================\n`;
                        fs.appendFileSync(wholePagePath, fileHeader + code);
                        scriptCollectedCount++;
                    }
                } catch (e) { }
            });

            try {
                await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(e => {
                    console.error(`    [Info] Connection delayed (forced scroll with partial load): ${e.message}`);
                });

                await Promise.race([
                    page.evaluate(async () => {
                        await new Promise(resolve => {
                            let totalHeight = 0, distance = 300;
                            const timer = setInterval(() => {
                                window.scrollBy(0, distance);
                                totalHeight += distance;
                                if (totalHeight >= document.body.scrollHeight || totalHeight > 50000) {
                                    clearInterval(timer);
                                    resolve();
                                }
                            }, 150);
                        });
                    }),
                    new Promise((_, reject) => setTimeout(() => reject(new Error("Scroll timeout")), 45000))
                ]);

                await new Promise(r => setTimeout(r, 2000));

            } catch (err) {
                console.error(`    [Info] Timeout or error during page load/scroll (collected files preserved): ${err.message}`);
            }

            const networkLogPath = path.join(siteDir, 'network_logs.json');
            fs.writeFileSync(networkLogPath, JSON.stringify(Array.from(interceptedUrls), null, 2));

            let actualSavedFiles = 0;
            if (fs.existsSync(siteDir)) {
                actualSavedFiles = Math.max(0, fs.readdirSync(siteDir).length - 1);
            }

            if (actualSavedFiles > 0) {
                crawlerStats.success++;
                console.log(    [Success]  -  scripts collected);
            } else {
                crawlerStats.fail++;
                console.log(    [Failed]  - No scripts collected (moved to fail_scripts));
                try {
                    await page.screenshot({ path: path.join(FAIL_ROOT, `${hostname}_blocked.png`), fullPage: false }).catch(() => { });
                    const failDir = path.join(FAIL_ROOT, hostname);
                    if (fs.existsSync(siteDir)) {
                        if (fs.existsSync(failDir)) fs.rmSync(failDir, { recursive: true, force: true });
                        fs.renameSync(siteDir, failDir);
                    }
                    fs.appendFileSync(path.join(FAIL_ROOT, 'failed_urls.txt'), targetUrl + '\n');
                } catch (e) {
                }
            }
        });

        for (const url of urls) cluster.queue(url);

        await cluster.idle();
        await cluster.close();

        const endTime = new Date();
        const diffMs = endTime - startTime;
        const diffMins = Math.floor(diffMs / 60000);
        const diffSecs = Math.floor((diffMs % 60000) / 1000);

        console.log(`\n================================`);
        console.log(` Total Crawling Report`);
        console.log(`================================`);
        console.log(` Start: ${startTime.toLocaleString()}`);
        console.log(` End  : ${endTime.toLocaleString()}`);
        console.log(` Time : ${diffMins}m ${diffSecs}s`);
        console.log(`--------------------------------`);
        console.log(` Success: ${crawlerStats.success} sites (collected_scripts)`);
        console.log(` Fail  : ${crawlerStats.fail} sites (fail_scripts)`);
        console.log(`================================\n`);

    } catch (err) {
        console.error("Critical Crawler Error:", err);
    } finally {
        console.log('\n>>> [System] Starting Mandatory Post-Processing...');

        if (fs.existsSync(OUTPUT_ROOT)) {
            const sites = fs.readdirSync(OUTPUT_ROOT);
            for (const site of sites) {
                const wholePagePath = path.join(OUTPUT_ROOT, site, 'wholepage.js');
                if (fs.existsSync(wholePagePath)) {
                    try {
                        let content = fs.readFileSync(wholePagePath, 'utf-8');

                        if (content) {
                            const cleaned = content.replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

                            if (content !== cleaned) {
                                fs.writeFileSync(wholePagePath, cleaned, 'utf-8');
                                console.log(`    [Fixed] Sanitized ${site}/wholepage.js (Removed Unicode Line Separators)`);
                            }
                        }
                    } catch (e) {
                        console.error(`    [Error] Post-processing failed for ${site}: ${e.message}`);
                    }
                }
            }
        }
        console.log('>>> [System] Post-Processing Complete. Exiting.');
    }
})();