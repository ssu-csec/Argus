/**
 * Test: URL validation (should be false positive)
 * Expected: POTENTIAL FALSE POSITIVE - URL validated but conservative analysis flags
 */

function isValidUrl(url) {
  try {
    new URL(url);
    return url.startsWith('https://trusted.com/');
  } catch (e) {
    return false;
  }
}

function test() {
  var redirect = new URLSearchParams(window.location.search).get('redirect');
  
  if (isValidUrl(redirect)) {
    window.location.href = redirect;
  }
}

test();