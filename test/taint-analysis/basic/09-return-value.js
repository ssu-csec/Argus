/**
 * Test: Return value propagation
 * Expected: VULNERABILITY - referrer through return value to innerHTML
 */

function getSource() {
  return document.referrer;
}

function test() {
  var source = getSource();
  document.body.innerHTML = "From: " + source;
}

test();