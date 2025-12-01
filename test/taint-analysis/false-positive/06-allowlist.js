/**
 * Test: Allowlist filtering (should be false positive)
 * Expected: POTENTIAL FALSE POSITIVE - allowlist checked but conservative analysis flags
 */

function test() {
  var allowedValues = ['option1', 'option2', 'option3'];
  var userChoice = new URLSearchParams(window.location.search).get('choice');
  
  if (allowedValues.includes(userChoice)) {
    document.body.innerHTML = 'Selected: ' + userChoice;
  }
}

test();