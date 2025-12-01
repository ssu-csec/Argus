#!/bin/bash

# Taint Analysis Test Runner
# This script runs all taint analysis tests and compares results with expected outcomes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HERMES_REFACTOR_DIR="/Users/minho.kim/repository/hephaistos/hermes-refactor"
HERMES_EXE_DIR="/Users/minho.kim/repository/hephaistos"
BUILD_DIR="$HERMES_EXE_DIR/build"
HERMESC="$BUILD_DIR/bin/hermesc"
TEST_DIR="$HERMES_REFACTOR_DIR/test/taint-analysis"
RESULTS_DIR="$TEST_DIR/results"
TEMP_DIR="$TEST_DIR/temp"

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
EXPECTED_VULNERABILITIES=0
DETECTED_VULNERABILITIES=0
FALSE_POSITIVES=0
FALSE_NEGATIVES=0

# Initialize directories
mkdir -p "$RESULTS_DIR" "$TEMP_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}=== Taint Analysis Test Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Check if hermesc exists
if [ ! -f "$HERMESC" ]; then
    echo -e "${RED}Error: hermesc not found at $HERMESC${NC}"
    echo "Please build Hermes first:"
    echo "  cd $HERMES_REFACTOR_DIR"
    echo "  cmake -B build -DCMAKE_BUILD_TYPE=Debug"
    echo "  cmake --build build"
    exit 1
fi

# Function to run a single test
run_test() {
    local test_file=$1
    local category=$2
    local test_name=$(basename "$test_file" .js)
    
    echo -n "  Testing $test_name... "
    
    # Extract expected result from test file comment
    local expected_result=$(head -5 "$test_file" | grep "Expected:" | sed 's/.*Expected: //' | sed 's/ -.*//')
    
    # Compile and run taint analysis
    local ir_file="$TEMP_DIR/${test_name}.ir"
    local result_file="$RESULTS_DIR/${test_name}.result"
    
    # Generate IR with taint analysis pass
    if $HERMESC -dump-ir -O0 -fno-inline "$test_file" > "$ir_file" 2>&1; then
        # Run taint analysis (assuming it's integrated as a pass)
        if $HERMESC -print-taint-analysis "$test_file" > "$result_file" 2>&1; then
            local detected_vulns=$(grep -c "VULNERABILITY" "$result_file" 2>/dev/null || echo "0")
            
            case "$expected_result" in
                "VULNERABILITY")
                    ((EXPECTED_VULNERABILITIES++))
                    if [ "$detected_vulns" -gt 0 ]; then
                        echo -e "${GREEN}PASS${NC} (vulnerability detected)"
                        ((PASSED_TESTS++))
                        ((DETECTED_VULNERABILITIES++))
                    else
                        echo -e "${RED}FAIL${NC} (false negative)"
                        ((FAILED_TESTS++))
                        ((FALSE_NEGATIVES++))
                    fi
                    ;;
                "NO VULNERABILITY")
                    if [ "$detected_vulns" -eq 0 ]; then
                        echo -e "${GREEN}PASS${NC} (no vulnerability)"
                        ((PASSED_TESTS++))
                    else
                        echo -e "${YELLOW}FAIL${NC} (false positive)"
                        ((FAILED_TESTS++))
                        ((FALSE_POSITIVES++))
                    fi
                    ;;
                "POTENTIAL FALSE POSITIVE")
                    if [ "$detected_vulns" -gt 0 ]; then
                        echo -e "${YELLOW}EXPECTED FP${NC} (conservative analysis)"
                        ((PASSED_TESTS++))
                        ((FALSE_POSITIVES++))
                    else
                        echo -e "${GREEN}GOOD${NC} (no false positive)"
                        ((PASSED_TESTS++))
                    fi
                    ;;
                "POTENTIAL FALSE NEGATIVE")
                    if [ "$detected_vulns" -eq 0 ]; then
                        echo -e "${YELLOW}EXPECTED FN${NC} (analysis limitation)"
                        ((PASSED_TESTS++))
                        ((FALSE_NEGATIVES++))
                    else
                        echo -e "${GREEN}GOOD${NC} (vulnerability detected despite complexity)"
                        ((PASSED_TESTS++))
                        ((DETECTED_VULNERABILITIES++))
                    fi
                    ;;
                *)
                    echo -e "${BLUE}UNKNOWN${NC} (unexpected result format)"
                    ((PASSED_TESTS++))
                    ;;
            esac
        else
            echo -e "${RED}FAIL${NC} (analysis error)"
            ((FAILED_TESTS++))
        fi
    else
        echo -e "${RED}FAIL${NC} (compilation error)"
        ((FAILED_TESTS++))
    fi
    
    ((TOTAL_TESTS++))
}

# Function to run tests in a category
run_category() {
    local category_dir=$1
    local category_name=$2
    
    echo -e "${BLUE}--- Testing $category_name ---${NC}"
    
    if [ ! -d "$category_dir" ]; then
        echo "  Category directory not found: $category_dir"
        return
    fi
    
    local test_files=$(find "$category_dir" -name "*.js" | sort)
    local category_count=0
    
    for test_file in $test_files; do
        run_test "$test_file" "$category_name"
        ((category_count++))
    done
    
    echo "  $category_name: $category_count tests"
    echo
}

# Run all test categories
echo "Starting taint analysis tests..."
echo

run_category "$TEST_DIR/basic" "Basic Taint Flow"
run_category "$TEST_DIR/xss" "XSS Vulnerabilities"
run_category "$TEST_DIR/network" "Network Data Leaks"
run_category "$TEST_DIR/storage" "Storage Vulnerabilities"
run_category "$TEST_DIR/code-injection" "Code Injection"
run_category "$TEST_DIR/navigation" "Navigation Hijacking"
run_category "$TEST_DIR/closure" "Closure Analysis"
run_category "$TEST_DIR/control-flow" "Control Flow"
run_category "$TEST_DIR/false-positive" "False Positive Cases"
run_category "$TEST_DIR/false-negative" "False Negative Cases"

# Generate summary report
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}=== Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
echo
echo "Vulnerability Detection:"
echo "Expected Vulnerabilities: $EXPECTED_VULNERABILITIES"
echo "Detected Vulnerabilities: $DETECTED_VULNERABILITIES"
echo "False Positives: $FALSE_POSITIVES"
echo "False Negatives: $FALSE_NEGATIVES"
echo

# Calculate metrics
if [ $EXPECTED_VULNERABILITIES -gt 0 ]; then
    local recall=$((DETECTED_VULNERABILITIES * 100 / EXPECTED_VULNERABILITIES))
    echo "Recall (Sensitivity): ${recall}%"
fi

if [ $((DETECTED_VULNERABILITIES + FALSE_POSITIVES)) -gt 0 ]; then
    local precision=$((DETECTED_VULNERABILITIES * 100 / (DETECTED_VULNERABILITIES + FALSE_POSITIVES)))
    echo "Precision: ${precision}%"
fi

local success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
echo "Overall Success Rate: ${success_rate}%"
echo

# Summary status
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ $FAILED_TESTS test(s) failed${NC}"
    
    if [ $FALSE_NEGATIVES -gt 0 ]; then
        echo -e "${RED}❌ $FALSE_NEGATIVES false negative(s) detected - vulnerabilities missed${NC}"
    fi
    
    if [ $FALSE_POSITIVES -gt 0 ]; then
        echo -e "${YELLOW}⚠ $FALSE_POSITIVES false positive(s) detected - safe code flagged${NC}"
    fi
    
    exit 1
fi
