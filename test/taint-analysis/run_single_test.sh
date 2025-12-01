#!/bin/bash

# Single Test Runner for Taint Analysis
# Usage: ./run_single_test.sh <test_file.js>

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ $# -ne 1 ]; then
    echo "Usage: $0 <test_file.js>"
    echo "Example: $0 basic/01-simple-source-sink.js"
    exit 1
fi

TEST_FILE=$1
HERMES_EXE_DIR="/Users/minho.kim/repository/hephaistos"
HERMES_REFACTOR_DIR="/Users/minho.kim/repository/hephaistos/hermes-refactor"
BUILD_DIR="$HERMES_EXE_DIR/build"
HERMESC="$BUILD_DIR/bin/hermesc"
TEST_DIR="$HERMES_REFACTOR_DIR/test/taint-analysis"

# Check if test file exists
if [ ! -f "$TEST_DIR/$TEST_FILE" ]; then
    echo -e "${RED}Error: Test file not found: $TEST_DIR/$TEST_FILE${NC}"
    exit 1
fi

# Check if hermesc exists
if [ ! -f "$HERMESC" ]; then
    echo -e "${RED}Error: hermesc not found at $HERMESC${NC}"
    echo "Please build Hermes first."
    exit 1
fi

echo -e "${BLUE}Running single taint analysis test${NC}"
echo "Test file: $TEST_FILE"
echo

# Extract expected result
EXPECTED_RESULT=$(head -5 "$TEST_DIR/$TEST_FILE" | grep "Expected:" | sed 's/.*Expected: //' | sed 's/ -.*//')
echo "Expected result: $EXPECTED_RESULT"
echo

# Show test code
echo -e "${BLUE}--- Test Code ---${NC}"
cat "$TEST_DIR/$TEST_FILE"
echo
echo -e "${BLUE}--- Analysis Results ---${NC}"

# Run taint analysis
if $HERMESC -dump-ir -O0 "$TEST_DIR/$TEST_FILE" 2>&1 | grep -E "(VULNERABILITY|Source:|Sink:|Path:)" || echo "No vulnerabilities detected"; then
    echo
    echo -e "${GREEN}✓ Analysis completed${NC}"
else
    echo
    echo -e "${RED}✗ Analysis failed${NC}"
    exit 1
fi
