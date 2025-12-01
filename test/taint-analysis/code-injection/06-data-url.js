/**
 * Test: Code injection via data URL
 * Expected: VULNERABILITY - cookie to data URL iframe
 */

function test() {
  var data = document.cookie;
  var iframe = document.createElement('iframe');
  iframe.src = 'data:text/html,<script>alert("' + data + '")</script>';
  document.body.appendChild(iframe);
}

test();