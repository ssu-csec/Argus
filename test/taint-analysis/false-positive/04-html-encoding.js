/**
 * Test: HTML encoding (should be false positive)
 * Expected: POTENTIAL FALSE POSITIVE - HTML encoded but conservative analysis flags
 */

function htmlEncode(str) {
  return str.replace(/[&<>"']/g, function(match) {
    var entities = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;'
    };
    return entities[match];
  });
}

function test() {
  var userInput = window.location.search;
  var safe = htmlEncode(userInput);
  document.body.innerHTML = safe;
}

test();