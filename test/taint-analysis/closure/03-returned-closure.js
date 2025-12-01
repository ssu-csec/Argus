/**
 * Test: Taint through returned closure
 * Expected: VULNERABILITY - cookie captured and used later
 */

function makeInjector() {
  var data = document.cookie;
  return function() {
    eval(data);
  };
}

function test() {
  var injector = makeInjector();
  injector();
}

test();
