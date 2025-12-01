/**
 * Test: Taint through computed property (may not be detected)
 * Expected: POTENTIAL FALSE NEGATIVE - computed property limitation
 */

function test() {
  var secret = document.cookie;
  var obj = {};
  var key = 'data';
  
  obj[key] = secret;
  document.body.innerHTML = obj['data'];
}

test();