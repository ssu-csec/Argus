/**
 * Test: Taint through switch statement
 * Expected: VULNERABILITY - different sources merged to eval
 */

function test(mode) {
  var data;
  
  switch(mode) {
    case 'cookie':
      data = document.cookie;
      break;
    case 'url':
      data = window.location.href;
      break;
    default:
      data = navigator.userAgent;
  }
  
  eval(data);
}

test('cookie');
