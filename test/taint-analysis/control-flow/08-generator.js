/**
 * Test: Generator function with taint
 * Expected: VULNERABILITY - userAgent through generator to eval
 */

function* dataGenerator() {
  var ua = navigator.userAgent;
  yield ua;
  yield "processed: " + ua;
}

function test() {
  var gen = dataGenerator();
  var result = gen.next().value;
  eval('console.log("' + result + '")');
}

test();