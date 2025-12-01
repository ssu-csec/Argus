/**
 * Test: Taint through object property (may not be detected)
 * Expected: POTENTIAL FALSE NEGATIVE - object tracking limitation
 */

function test() {
  var obj = {};
  obj.data = document.cookie;
  document.body.innerHTML = obj.data;
}

test();
