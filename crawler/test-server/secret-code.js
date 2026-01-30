// // 이 파일은 크롤러가 가져가야 합니다.
// function verificationFunction() {
//     var goldenKey = "HEPHAISTOS_VERIFICATION_SUCCESS_2026"; // ★ 이 문자열을 찾을 겁니다.
//     console.log("If you see this, the crawler is working.");
    
//     // 난독화 해제 성능 테스트용 (간단한 난독화)
//     var _0x1234 = ['log', 'Hello World'];
//     console[_0x1234[0]](_0x1234[1]);
// }
// verificationFunction();

// [Complex Tracker Simulation]
// 실제 악성 스크립트처럼 난독화 기법(Hex String, Control Flow)을 흉내 낸 코드입니다.

(function() {
    // 1. 문자열 숨김 (Hex Encoding)
    var _0x1a2b = {
        'cookieName': '\x75\x69\x64', // "uid"
        'storageKey': '\x62\x61\x63\x6b\x75\x70\x5f\x69\x64', // "backup_id"
        'trackerUrl': '\x68\x74\x74\x70\x3a\x2f\x2f\x61\x64\x2e\x63\x6f\x6d\x2f\x6c\x6f\x67' // "http://ad.com/log"
    };

    // 2. 사용자 식별자 생성 (Source)
    function generateUUID() {
        var d = new Date().getTime(); // Source: Time
        var nav = navigator.userAgent; // Source: UserAgent
        return 'user_' + d + '_' + nav.length; 
    }

    // 3. 데이터 저장 (Sink: Cookie & LocalStorage)
    function saveIdentity(_id) {
        // (A) 쿠키 저장 (Sink)
        document.cookie = _0x1a2b['cookieName'] + '=' + _id + '; path=/';
        
        // (B) 로컬 스토리지 저장 (Sink - 혼합 추적)
        window.localStorage.setItem(_0x1a2b['storageKey'], _id);
    }

    // 4. 데이터 전송 (Sink: Network)
    function sendBeacon(_id) {
        var img = new Image();
        // Source(ID) -> Sink(Image.src) 흐름
        img.src = _0x1a2b['trackerUrl'] + '?id=' + _id + '&ref=' + document.referrer;
    }

    // [실행 흐름]
    var trackingID = generateUUID(); // 1. ID 생성
    saveIdentity(trackingID);        // 2. 저장 (Storage Vulnerability)
    sendBeacon(trackingID);          // 3. 전송 (Network Vulnerability)

    console.log("Tracker Loaded. ID:", trackingID);
})();