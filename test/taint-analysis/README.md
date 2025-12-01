# Taint Analysis Test Suite

This comprehensive test suite validates the Hermes Taint Analysis implementation with **50+ carefully crafted test cases** covering various vulnerability scenarios and edge cases.

## 📁 Test Structure

```
test/taint-analysis/
├── basic/              # Basic taint flow scenarios (13 tests)
├── xss/                # Cross-Site Scripting vectors (10 tests)
├── network/            # Network data exfiltration (10 tests)
├── storage/            # Data storage vulnerabilities (6 tests)
├── code-injection/     # Code injection attacks (8 tests)
├── navigation/         # Navigation hijacking (7 tests)
├── closure/            # JavaScript closure scenarios (8 tests)
├── control-flow/       # Complex control flow (10 tests)
├── false-positive/     # Expected false positives (6 tests)
├── false-negative/     # Expected false negatives (6 tests)
├── run_tests.sh        # Main test runner
├── run_single_test.sh  # Single test runner
└── README.md           # This file
```

## 🚀 Running Tests

### Run All Tests
```bash
cd hermes-refactor/test/taint-analysis
./run_tests.sh
```

### Run Single Test
```bash
cd hermes-refactor/test/taint-analysis
./run_single_test.sh basic/01-simple-source-sink.js
```

### Build Requirements
First, ensure Hermes is built with taint analysis:
```bash
cd hermes-refactor
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## 📊 Test Categories

### 1. Basic Taint Flow (13 tests)
**Purpose**: Validate fundamental taint propagation mechanisms

| Test | Description | Expected |
|------|-------------|----------|
| 01-simple-source-sink | `navigator.userAgent` → `innerHTML` | VULNERABILITY |
| 02-multi-assignment | Cookie through multiple variables to `eval` | VULNERABILITY |
| 03-binary-operation | UserAgent + string to `innerHTML` | VULNERABILITY |
| 04-phi-node | Referrer through if-else to `fetch` | VULNERABILITY |
| 05-no-vulnerability | Safe hardcoded string | NO VULNERABILITY |
| 06-complex-event | Multiple sources in event handler | VULNERABILITY |
| 07-async-callback | Cookie through setTimeout to fetch | VULNERABILITY |
| 08-function-param | UserAgent through function parameter | VULNERABILITY |
| 09-return-value | Referrer through return value | VULNERABILITY |
| 10-destructuring | Cookie through array destructuring | VULNERABILITY |
| 11-phishing-scenario | Real-world phishing data collection | VULNERABILITY |
| 12-cryptojacking | Browser info for crypto mining config | VULNERABILITY |
| 13-fingerprinting | Comprehensive device fingerprinting | VULNERABILITY |

### 2. XSS Vulnerabilities (10 tests)
**Purpose**: Test Cross-Site Scripting detection capabilities

| Test | Description | Source → Sink |
|------|-------------|---------------|
| 01-innerHTML | URL param → `innerHTML` | ✓ |
| 02-outerHTML | Cookie → `outerHTML` | ✓ |
| 03-document-write | UserAgent → `document.write` | ✓ |
| 04-template-literal | Hash → template literal → `innerHTML` | ✓ |
| 05-event-handler | Search → event handler injection | ✓ |
| 06-dom-multi-step | Location search → multi-step DOM manipulation | ✓ |
| 07-setAttribute | Hash → `setAttribute('onclick')` | ✓ |
| 08-textContent-safe | Search → `textContent` (safe) | ✗ |
| 09-script-element | Hash → script element creation | ✓ |
| 10-multiple-vectors | Cookie → multiple XSS sinks | ✓ |

### 3. Network Data Leaks (10 tests)
**Purpose**: Detect sensitive data exfiltration

| Test | Vector | Source | Sink |
|------|--------|--------|------|
| 01-fetch-url | URL parameter | Cookie | `fetch` URL |
| 02-fetch-body | Request body | localStorage | `fetch` body |
| 03-xhr-open | XHR URL | Referrer | `xhr.open` |
| 04-xhr-send | XHR body | Cookie | `xhr.send` |
| 05-sendbeacon | Beacon data | UserAgent | `sendBeacon` |
| 06-websocket | WebSocket message | UserAgent | WebSocket |
| 07-image-src | Image tracking | Cookie | `img.src` |
| 08-eventsource | EventSource URL | Referrer | EventSource |
| 09-form-action | Form submission | URL params | form action |
| 10-jsonp-leak | JSONP callback | Cookie | script src |

### 4. Storage Vulnerabilities (6 tests)
**Purpose**: Detect sensitive data storage issues

- localStorage.setItem with cookie data
- sessionStorage.setItem with URL data  
- document.cookie writes with referrer
- IndexedDB storage with userAgent
- Cache API storage with cookie
- WebSQL storage with URL data

### 5. Code Injection (8 tests)
**Purpose**: Detect dynamic code execution vulnerabilities

- Direct `eval()` with URL hash
- `Function()` constructor with search params
- `setTimeout()` string execution with cookie
- `setInterval()` string execution with URL
- `javascript:` URL with hash
- Data URL iframe with cookie
- Dynamic `import()` with search
- Web Worker script injection

### 6. Navigation Hijacking (7 tests)
**Purpose**: Detect redirect and navigation attacks

- `location.href` assignment
- `location.assign()` call
- `location.replace()` call
- `window.open()` call
- `history.pushState()` manipulation
- Meta refresh redirect
- Iframe src manipulation

### 7. Closure Analysis (8 tests)
**Purpose**: Test JavaScript closure taint tracking

- Simple closure variable capture
- Nested closure chains
- Returned closure functions
- Closure variable modification
- Callback closure with setTimeout
- Parameter modification in closure
- Array element capture in closure
- Event listener closure

### 8. Control Flow (10 tests)
**Purpose**: Test complex control flow scenarios

- For loop taint accumulation
- While loop processing
- Switch statement merging
- Try-catch-finally blocks
- Ternary operator branching
- Promise chain propagation
- Async/await taint flow
- Generator function yields
- Recursive function calls
- Exception handling

### 9. False Positive Cases (6 tests)
**Purpose**: Test conservative analysis behavior

- Sanitized input (HTML encoding)
- Constant override of tainted variable
- Type conversion (number parsing)
- URL validation before redirect
- Allowlist filtering
- Input validation

### 10. False Negative Cases (6 tests)
**Purpose**: Test analysis limitations

- Object property tracking
- Array element tracking  
- Indirect function calls
- Prototype chain pollution
- Computed property access
- Complex eval contexts

## 📈 Expected Results

### Vulnerability Distribution
- **Basic flows**: 13 vulnerabilities
- **XSS vectors**: 9 vulnerabilities (1 safe case)
- **Network leaks**: 10 vulnerabilities
- **Storage issues**: 6 vulnerabilities
- **Code injection**: 8 vulnerabilities
- **Navigation**: 7 vulnerabilities
- **Total**: ~53 expected vulnerabilities

### Analysis Metrics
- **Recall**: % of actual vulnerabilities detected
- **Precision**: % of detections that are actual vulnerabilities
- **False Positive Rate**: Conservative analysis tradeoffs
- **False Negative Rate**: Analysis limitation cases

## 🔧 Test Format

Each test file follows this structure:

```javascript
/**
 * Test: Description of the test scenario
 * Expected: VULNERABILITY|NO VULNERABILITY|POTENTIAL FALSE POSITIVE|POTENTIAL FALSE NEGATIVE
 */

function test() {
  // Test scenario code
  var source = navigator.userAgent;  // Source
  document.body.innerHTML = source;   // Sink
}

test();
```

## 🎯 Usage Examples

### Example: Running XSS Tests
```bash
# Run all XSS tests
find test/taint-analysis/xss -name "*.js" | while read test; do
  echo "Testing: $test"
  ./run_single_test.sh "xss/$(basename $test)"
done
```

### Example: Checking Analysis Output
```bash
# Generate IR with taint analysis
./build/bin/hermesc -dump-ir -O0 test/taint-analysis/basic/01-simple-source-sink.js

# Look for taint analysis results
grep -E "(VULNERABILITY|Source:|Sink:|Path:)" output.ir
```

## 📝 Adding New Tests

1. **Create test file** in appropriate category directory
2. **Add header comment** with expected result
3. **Write test function** with source→sink flow
4. **Call test function** at the end
5. **Run test** to verify behavior

Example template:
```javascript
/**
 * Test: Your test description here
 * Expected: VULNERABILITY
 */

function test() {
  var source = /* your source here */;
  /* your sink here */ = source;
}

test();
```

## 🚀 Integration with CI/CD

The test suite can be integrated into continuous integration:

```yaml
# .github/workflows/taint-analysis.yml
- name: Run Taint Analysis Tests
  run: |
    cd hermes-refactor
    cmake -B build -DCMAKE_BUILD_TYPE=Debug
    cmake --build build
    test/taint-analysis/run_tests.sh
```

## 📊 Performance Expectations

- **Small tests** (< 50 LOC): < 1 second per test
- **Complex tests**: < 5 seconds per test  
- **Full suite**: < 5 minutes total
- **Memory usage**: < 500MB peak

## 🐛 Troubleshooting

### Build Issues
```bash
# Clean rebuild
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### Test Failures
```bash
# Check individual test
./run_single_test.sh basic/01-simple-source-sink.js

# Check hermesc directly
./build/bin/hermesc -help | grep taint
```

### Missing Output
- Ensure taint analysis pass is registered in PassManager
- Check TaintAnalysis.cpp compilation
- Verify CMakeLists.txt includes all source files

---

## 🎯 Goals

This test suite validates:
1. ✅ **Source identification**: 100+ JavaScript APIs
2. ✅ **Sink detection**: 20+ vulnerability categories  
3. ✅ **Taint propagation**: Through def-use chains
4. ✅ **Closure tracking**: JavaScript-specific features
5. ✅ **Path recording**: Complete vulnerability traces
6. ✅ **Real-world scenarios**: Practical attack vectors

**Total Test Coverage**: 50+ tests across 10 categories
**Expected Vulnerabilities**: ~53 unique scenarios
**Analysis Features**: Conservative, path-recording, closure-aware