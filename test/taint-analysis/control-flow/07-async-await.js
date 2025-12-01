/**
 * Test: Async/await with taint
 * Expected: VULNERABILITY - cookie through async/await to innerHTML
 */

async function test() {
  var secret = await Promise.resolve(document.cookie);
  var processed = await Promise.resolve('Data: ' + secret);
  document.body.innerHTML = processed;
}

test();