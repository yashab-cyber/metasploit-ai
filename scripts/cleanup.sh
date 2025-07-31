#!/bin/bash
# Metasploit-AI Framework Cleanup Script
# Removes cache files, temporary files, and organizes the project structure

echo "🧹 Starting Metasploit-AI Framework cleanup..."

# Remove Python cache files
echo "Removing Python cache files..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "*.pyo" -delete 2>/dev/null || true

# Remove log files (keep directories)
echo "Cleaning log files..."
find logs/ -name "*.log" -delete 2>/dev/null || true

# Remove temporary files
echo "Removing temporary files..."
find . -name "*.tmp" -delete 2>/dev/null || true
find . -name "*.temp" -delete 2>/dev/null || true
find . -name "*~" -delete 2>/dev/null || true
find . -name "*.bak" -delete 2>/dev/null || true

# Remove test coverage files
echo "Cleaning test coverage files..."
rm -rf htmlcov/ 2>/dev/null || true
rm -f .coverage 2>/dev/null || true

# Remove build artifacts
echo "Removing build artifacts..."
rm -rf build/ 2>/dev/null || true
rm -rf dist/ 2>/dev/null || true
rm -rf *.egg-info/ 2>/dev/null || true

# Clean data directory (keep structure)
echo "Cleaning data directory..."
find data/ -name "*.tmp" -delete 2>/dev/null || true
find data/ -name "*.temp" -delete 2>/dev/null || true

# Ensure directory structure exists
echo "Ensuring directory structure..."
mkdir -p data logs models reports tests

# Check for misplaced test files
echo "Checking for misplaced test files..."
if ls test_*.py 1> /dev/null 2>&1; then
    echo "Moving test files to tests/ directory..."
    mv test_*.py tests/ 2>/dev/null || true
fi

echo "✅ Cleanup completed successfully!"
echo ""
echo "📊 Directory structure:"
tree -I '__pycache__|*.pyc|*.log' -L 2 || ls -la

echo ""
echo "🔍 Cleanup summary:"
echo "- Removed Python cache files (__pycache__, *.pyc)"
echo "- Cleaned temporary and backup files"
echo "- Removed build artifacts"
echo "- Organized test files in tests/ directory"
echo "- Ensured proper directory structure"
echo ""
echo "Ready for development or deployment! 🚀"
