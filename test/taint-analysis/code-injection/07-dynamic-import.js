/**
 * Test: Dynamic import code injection
 * Expected: VULNERABILITY - URL search to dynamic import
 */

function test() {
  var module = window.location.search.substring(1);
  import(module).then(function(m) {
    m.default();
  });
}

test();