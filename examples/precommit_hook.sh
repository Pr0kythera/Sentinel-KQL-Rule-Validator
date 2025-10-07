#!/bin/bash

# Git Pre-Commit Hook for Sentinel Detection Linter
# 
# To install this hook:
#   1. Copy this file to .git/hooks/pre-commit
#   2. Make it executable: chmod +x .git/hooks/pre-commit
#
# This hook will:
#   - Detect YAML files being committed
#   - Run the linter on them
#   - Prevent commit if validation fails

# Path to the linter (adjust if needed)
LINTER_PATH="python linter.py"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Running Sentinel Detection Linter pre-commit hook...${NC}"
echo ""

# Get list of YAML files staged for commit
YAML_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(yaml|yml)$')

if [ -z "$YAML_FILES" ]; then
    echo -e "${GREEN}No YAML files to validate.${NC}"
    exit 0
fi

# Count files
FILE_COUNT=$(echo "$YAML_FILES" | wc -l)
echo "Validating $FILE_COUNT YAML file(s)..."
echo ""

# Validate each file
ALL_PASSED=true

for FILE in $YAML_FILES; do
    echo "Validating: $FILE"
    
    # Run linter on the file
    if $LINTER_PATH "$FILE" > /dev/null 2>&1; then
        echo -e "${GREEN}  PASSED${NC}"
    else
        echo -e "${RED}  FAILED${NC}"
        ALL_PASSED=false
        
        # Show the errors
        echo -e "${YELLOW}  Errors:${NC}"
        $LINTER_PATH "$FILE" 2>&1 | grep -E '\[ERROR\]|\[FAIL\]' | sed 's/^/    /'
    fi
    echo ""
done

# Check results
if [ "$ALL_PASSED" = true ]; then
    echo -e "${GREEN}All validation checks passed!${NC}"
    echo -e "${GREEN}Proceeding with commit...${NC}"
    exit 0
else
    echo -e "${RED}Validation failed!${NC}"
    echo ""
    echo "Some detection files have validation errors."
    echo "Please fix the errors before committing."
    echo ""
    echo "To see detailed errors, run:"
    for FILE in $YAML_FILES; do
        echo "  python linter.py $FILE"
    done
    echo ""
    echo "To bypass this check (not recommended), use:"
    echo "  git commit --no-verify"
    echo ""
    exit 1
fi
