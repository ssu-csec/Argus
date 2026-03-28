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
const FAIL_ROOT = './fail_scripts';
if (!fs.existsSync(FAIL_ROOT)) fs.mkdirSync(FAIL_ROOT);

let crawlerStats = { success: 0, fail: 0 };

// ★ 메인 로직 전체를 감싸서 안전장치 확보
(async () => {
    const startTime = new Date(); // 크롤링 시작 시간 기록
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
                .filter(l => l && !l.startsWith('#'))
                .map(l => {
                    // Tranco 리스트(1,google.com) 형식 지원
                    const parts = l.split(',');
                    return parts.length > 1 ? parts[1].trim() : l;
                });
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

            // 🌟 [하이브리드 분석용] 모든 통신 패킷 URL을 담을 콜렉션
            const interceptedUrls = new Set();

            const { Deobfuscator } = await import('restringer');
            const babel = require('@babel/core');
            const beautify = require('js-beautify').js;

            await page.setRequestInterception(true);
            page.on('request', req => {
                const rType = req.resourceType();
                const reqUrl = req.url();

                // 🌟 [하이브리드 분석용] HTTP(S)로 나가는 모든 외부 요청의 주소를 캡처하여 저장 (결과 교차검증에 사용)
                if (reqUrl.startsWith('http')) {
                    interceptedUrls.add(reqUrl);
                }

                // [수정] stylesheet와 other를 차단하면 최신 SPA 웹사이트들이 로딩을 멈추고 타임아웃에 빠질 수 있으므로 허용합니다.
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

                        // [개선] 4. 초대형 스크립트(250KB 초과)는 파싱, 디옵스케이트 시 Node 이벤트 루프를 장시간 멈추게 하므로(서버 먹통) 그대로 바이패스
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

                        // ★ [수정] 인-스트림 안전장치 강화
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
                // [개선] 1. 완벽한 로딩(networkidle)을 기다리지 않고, DOM 문서만 열려도 즉시 스크롤 시작
                // 타겟에 따라 무한 로딩이 걸리는 리소스를 무시하기 위함
                // [추가개선] goto 통신 자체가 타임아웃 나더라도 에러로 끊지 않고, 일단 로딩된 데까지만이라도 스크롤 시도하도록 catch 분리
                await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(e => {
                    console.error(`    [Info] ❗ 접속 지연 (일부만 로드된 상태로 강제 스크롤 시도): ${e.message}`);
                });

                // [개선] 2. 스크롤 동작에도 자체 타임아웃 방어막(Promise.race) 적용
                await Promise.race([
                    page.evaluate(async () => {
                        await new Promise(resolve => {
                            let totalHeight = 0, distance = 300; // 스크롤 속도 조금 더 빠르게
                            const timer = setInterval(() => {
                                window.scrollBy(0, distance);
                                totalHeight += distance;
                                // 문서 끝에 도달하거나, 너무 깊이 내려가는 경우(방어적 제한) 멈춤
                                if (totalHeight >= document.body.scrollHeight || totalHeight > 50000) {
                                    clearInterval(timer);
                                    resolve();
                                }
                            }, 150);
                        });
                    }),
                    new Promise((_, reject) => setTimeout(() => reject(new Error("Scroll timeout")), 45000))
                ]);

                // 스크롤이 끝난 뒤 추가 로딩스크립트를 수집할 자투리 시간 2초 부여
                await new Promise(r => setTimeout(r, 2000));

            } catch (err) {
                // [개선] 3. 타임아웃이 나더라도 에러로 팅기지 않고, 지금까지 모은 JS가 있으면 정상 저장 취급
                console.error(`    [Info] 사이트 로드/스크롤 중 타임아웃 또는 에러 발생 (수집된 파일은 보존됨): ${err.message}`);
            }

            // 🌟 [하이브리드 분석용] (버그 수정) 타임아웃이 발생하더라도, 지금까지 잡아낸 통신 로그는 무조건 저장!
            const networkLogPath = path.join(siteDir, 'network_logs.json');
            fs.writeFileSync(networkLogPath, JSON.stringify(Array.from(interceptedUrls), null, 2));

            // [추가] 수집 여부에 따라 최종 디렉토리 이동 및 통계 집계
            let actualSavedFiles = 0;
            if (fs.existsSync(siteDir)) {
                // wholepage.js 하나 빼고 실제 저장된 스크립트 파일들 개수 측정
                actualSavedFiles = Math.max(0, fs.readdirSync(siteDir).length - 1);
            }

            if (actualSavedFiles > 0) {
                crawlerStats.success++;
                console.log(`    [✅ Success] ${hostname} - ${actualSavedFiles}개 스크립트 수집 완료 (폴더 내 파일 수)`);
            } else {
                crawlerStats.fail++;
                console.log(`    [❌ Failed] ${hostname} - 수집된 스크립트 없음 (fail_scripts 폴더로 이동)`);
                try {
                    await page.screenshot({ path: path.join(FAIL_ROOT, `${hostname}_blocked.png`), fullPage: false }).catch(() => { });
                    const failDir = path.join(FAIL_ROOT, hostname);
                    if (fs.existsSync(siteDir)) {
                        if (fs.existsSync(failDir)) fs.rmSync(failDir, { recursive: true, force: true });
                        fs.renameSync(siteDir, failDir);
                    }
                    // 실패한 도메인의 원본 URL을 fail_scripts 폴더 내 txt 파일에 누적 기록
                    fs.appendFileSync(path.join(FAIL_ROOT, 'failed_urls.txt'), targetUrl + '\n');
                } catch (e) {
                    // 파일 잠금 등으로 이동 실패 시 무시
                }
            }
        });

        for (const url of urls) cluster.queue(url);

        await cluster.idle();
        await cluster.close();

        const endTime = new Date(); // 크롤링 종료 시간 기록
        const diffMs = endTime - startTime;
        const diffMins = Math.floor(diffMs / 60000);
        const diffSecs = Math.floor((diffMs % 60000) / 1000);

        console.log(`\n================================`);
        console.log(` 📝 Total Crawling Report`);
        console.log(`================================`);
        console.log(` ⏳ Start: ${startTime.toLocaleString()}`);
        console.log(` ⌛ End  : ${endTime.toLocaleString()}`);
        console.log(` ⏱️ Time : ${diffMins}m ${diffSecs}s`);
        console.log(`--------------------------------`);
        console.log(` ✅ Success: ${crawlerStats.success} sites (collected_scripts)`);
        console.log(` ❌ Fail: ${crawlerStats.fail} sites (fail_scripts)`);
        console.log(`================================\n`);

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