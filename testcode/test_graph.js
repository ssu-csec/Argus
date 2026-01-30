// // test_graph.js (수정본)
// function sendData(data) {
//     // 3. 인자로 받은 data가 싱크로 들어감
//     // (Phase 5가 여기서 활약해야 함!)
//     localStorage.setItem("key", data);
// }

// function main() {
//     // 1. 오염원을 main에서 직접 생성 (Return 과정 생략)
//     var secret = document.cookie;

//     // 2. 함수 호출하면서 오염된 값 전달 (Link 테스트)
//     sendData(secret);
// }

// main();

// // test_return.js
// function checkCookie() {
//     return document.cookie; // 오염원 리턴
// }

// function main() {
//     var secret = checkCookie(); // 여기가 새로운 Source로 인식되어야 함!
//     localStorage.setItem("k", secret);
// }
// main();

// // test_global.js
// var globalData = ""; 

// function setTaint() {
//     // 1. 여기서 [Global Taint] Found... 로그가 떠야 함
//     globalData = document.cookie; 
// }

// function useTaint() {
//     // 2. 여기서 [Global Taint] Marking load... 로그가 떠야 함
//     localStorage.setItem("key", globalData); 
// }

// function main() {
//     setTaint();
//     useTaint();
// }

// main();

// ==========================================
// Test 1: Fingerprinting 추적 (인자 전달 방식)
// Source: navigator.userAgent (SourceDefinitions에 정의됨)
// Sink: localStorage.setItem
// ==========================================
function logDeviceInfo(info) {
    // [Phase 5] 인자 전달(Argument) 추적 동작 확인
    localStorage.setItem("device_log", info);
}

function testFingerprinting() {
    // navigator.userAgent는 레지스트리에 등록된 오염원입니다.
    var userAgent = navigator.userAgent; 
    logDeviceInfo(userAgent);
}


// ==========================================
// Test 2: DOM XSS 추적 (반환값 방식)
// Source: location.search (SourceDefinitions에 정의됨)
// Sink: eval (가정)
// ==========================================
function getMaliciousInput() {
    // [Hybrid] 반환값(Return) 추적 로직 확인
    // location.search는 URL 파라미터로, 대표적인 XSS 통로입니다.
    return location.search;
}

function testXSS() {
    var input = getMaliciousInput();
    // eval은 매우 위험한 Sink입니다. (SinkRegistry에 있다면 탐지됨)
    // 만약 eval이 Sink로 등록 안 되어 있다면 localStorage.setItem으로 바꾸세요.
    eval(input); 
}


// ==========================================
// Test 3: 네트워크 데이터 유출 (전역 변수 방식)
// Source: fetch (SourceDefinitions에 정의됨)
// Sink: localStorage.setItem
// ==========================================
var globalNetworkData = null; // 전역 변수 게시판

function fetchSecret() {
    // [Global Pre-scan] 전역 변수 쓰기 감지
    // fetch() 함수 호출 자체가 오염원입니다.
    globalNetworkData = fetch("https://api.secret.com/keys");
}

function leakSecret() {
    // [Global Pre-scan] 전역 변수 읽기 감지
    if (globalNetworkData) {
        localStorage.setItem("leaked_data", globalNetworkData);
    }
}

function testNetworkLeak() {
    fetchSecret();
    leakSecret();
}


// ==========================================
// Test 4: 정밀도(Precision) 테스트 (False Positive 검증)
// 설명: 이름이 비슷하지만 오염원이 아닌 경우 안 잡혀야 함
// ==========================================
function testFalsePositive() {
    var mySnack = {
        cookie: "chocochip" // 이름은 cookie지만, 객체가 document가 아님!
    };
    
    // 만약 분석기가 단순히 "cookie"라는 글자만 본다면 이걸 잡을 것입니다.
    // 하지만 객체 이름(mySnack)까지 본다면(방금 수정한 로직) 잡지 말아야 합니다.
    localStorage.setItem("safe_snack", mySnack.cookie);
}


// === 실행 ===
testFingerprinting(); // 탐지되어야 함 (1)
testXSS();            // 탐지되어야 함 (2)
testNetworkLeak();    // 탐지되어야 함 (3)
testFalsePositive();  // 탐지되면 안 됨 (0)