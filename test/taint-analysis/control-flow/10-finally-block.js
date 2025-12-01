/**
 * Test: Exception handling with taint
 * Expected: VULNERABILITY - finally block taint to innerHTML
 */

function test() {
  var data = navigator.userAgent;
  
  try {
    throw new Error("test");
  } catch (e) {
    // Do nothing
  } finally {
    document.body.innerHTML = "Finally: " + data;
  }
}

test();