/**
 * Test: WebSQL storage (deprecated but still risky)
 * Expected: VULNERABILITY - URL data to WebSQL
 */

function test() {
  var url = window.location.href;
  var db = openDatabase('TestDB', '1.0', 'Test Database', 2 * 1024 * 1024);
  
  db.transaction(function(tx) {
    tx.executeSql('CREATE TABLE IF NOT EXISTS logs (id, url)');
    tx.executeSql('INSERT INTO logs (id, url) VALUES (1, ?)', [url]);
  });
}

test();