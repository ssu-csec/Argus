const { Cluster } = require('puppeteer-cluster');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const iconv = require('iconv-lite');

// 플러그인 적용
puppeteer.use(StealthPlugin());

const OUTPUT_ROOT = './collected_scripts';
if (!fs.existsSync(OUTPUT_ROOT)) fs.mkdirSync(OUTPUT_ROOT);

// ★ 메인 로직 전체를 감싸서 안전장치 확보
(async () => {
    try {
        // 1. URL 리스트 파일 읽기
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
                .filter(l => l && !l.startsWith('#'));
        } catch (e) {
            console.error(`Error reading file: ${e.message}`);
            process.exit(1);
        }

        // 2. 클러스터 설정
        const cluster = await Cluster.launch({
            concurrency: Cluster.CONCURRENCY_BROWSER, // 안전 모드 (브라우저 격리)
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

        // 3. 작업 정의
        await cluster.task(async ({ page, data: targetUrl }) => {
            console.log(`\n>>> Processing: ${targetUrl}`);
            
            let hostname;
            try { hostname = new URL(targetUrl).hostname; } catch (e) { return; }

            const siteDir = path.join(OUTPUT_ROOT, hostname);
            if (!fs.existsSync(siteDir)) fs.mkdirSync(siteDir, { recursive: true });

            const wholePagePath = path.join(siteDir, 'wholepage.js');
            if (fs.existsSync(wholePagePath)) fs.unlinkSync(wholePagePath);
            fs.writeFileSync(wholePagePath, '\uFEFF'); 

            const { Deobfuscator } = await import('restringer');
            const babel = require('@babel/core');
            const beautify = require('js-beautify').js;

            await page.setRequestInterception(true);
            page.on('request', req => {
                const rType = req.resourceType();
                if (['image', 'media', 'font', 'stylesheet', 'other'].includes(rType)) {
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
                            } catch (e) {}
                        }

                        if (!code || code.trim().length === 0) return;

                        try {
                            const deobfuscator = new Deobfuscator(code, { unsafe: true, normalize: true, simplify: true });
                            const cleanCode = deobfuscator.deobfuscate();
                            if (cleanCode !== code) code = cleanCode;
                        } catch (e) {}

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
                        } catch (e) {}

                        try {
                            const formatted = beautify(code, { 
                                indent_size: 2, 
                                space_in_empty_paren: true, 
                                // ★ [수정] 유니코드 문자를 억지로 풀지 않도록 설정 (안전성 UP)
                                unescape_strings: false 
                            });
                            if (formatted && formatted.length > 0) code = formatted;
                        } catch (e) {}

                        // ★ [수정] 인-스트림 안전장치 강화
                        if (code) {
                            code = code.replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
                        }

                        const fileName = path.basename(new URL(rUrl).pathname) || 'script.js';
                        const safeName = fileName.replace(/[^a-z0-9.]/gi, '_') + '_' + Date.now() + '.js';
                        fs.writeFileSync(path.join(siteDir, safeName), code);

                        const fileHeader = `\n\n// ==========================================\n// [FILE] Source: ${rUrl}\n// ==========================================\n`;
                        fs.appendFileSync(wholePagePath, fileHeader + code);
                    }
                } catch (e) {}
            });

            try {
                await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 240000 });
                await page.evaluate(async () => {
                    await new Promise(resolve => {
                        let totalHeight = 0, distance = 200;
                        const timer = setInterval(() => {
                            window.scrollBy(0, distance);
                            totalHeight += distance;
                            if (totalHeight >= document.body.scrollHeight) {
                                clearInterval(timer);
                                resolve();
                            }
                        }, 200);
                    });
                });
                await new Promise(r => setTimeout(r, 2000));
            } catch (err) {
                console.error(`    [Info] 타임아웃 발생 (수집된 파일은 보존됨): ${err.message}`);
            }
        });

        for (const url of urls) cluster.queue(url);

        await cluster.idle();
        await cluster.close();

    } catch (err) {
        console.error("Critical Crawler Error:", err);
    } finally {
        // ============================================================
        // ★ [핵심] 좀비가 되어도 실행되는 "최후의 청소부" (Finally Block)
        // 크롤러가 죽든 말든 무조건 실행되어 파일을 고쳐놓습니다.
        // ============================================================
        console.log('\n>>> [System] Starting Mandatory Post-Processing...');
        
        if (fs.existsSync(OUTPUT_ROOT)) {
            const sites = fs.readdirSync(OUTPUT_ROOT);
            for (const site of sites) {
                const wholePagePath = path.join(OUTPUT_ROOT, site, 'wholepage.js');
                if (fs.existsSync(wholePagePath)) {
                    try {
                        let content = fs.readFileSync(wholePagePath, 'utf-8');
                        
                        // 숨겨진 유니코드 문자(U+2028, U+2029) 박멸
                        // 만약 content가 null이면 빈 문자열 처리
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
        // ============================================================
    }
})();