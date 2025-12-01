/**
 * Test: IndexedDB storage of sensitive data
 * Expected: VULNERABILITY - userAgent to IndexedDB
 */

function test() {
  var ua = navigator.userAgent;
  var request = indexedDB.open('UserData', 1);
  
  request.onsuccess = function(event) {
    var db = event.target.result;
    var transaction = db.transaction(['users'], 'readwrite');
    var store = transaction.objectStore('users');
    store.add({ id: 1, userAgent: ua });
  };
}

test();