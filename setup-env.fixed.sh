#!/bin/bash

# K8sMatrixWarden Environment Setup Script
# Detects Python versions, checks requirements, and sets up MCP environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}K8sMatrixWarden Setup Wizard${NC}"
echo -e "${BLUE}================================${NC}\n"

# ============================================================================
# Step 1: Extract Python requirement from pyproject.toml
# ============================================================================

echo -e "${YELLOW}[1/5] Reading Python requirements from pyproject.toml...${NC}"

if [ ! -f "$PROJECT_ROOT/pyproject.toml" ]; then
    echo -e "${RED}ERROR: pyproject.toml not found${NC}"
    exit 1
fi

# Extract requires-python from pyproject.toml (e.g., ">=3.10")
# Portable parse: no grep -P / \K (unsupported on BSD/macOS grep).
PYTHON_REQ=$(grep -E '^[[:space:]]*requires-python' "$PROJECT_ROOT/pyproject.toml" 2>/dev/null \
    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
[ -z "$PYTHON_REQ" ] && PYTHON_REQ=">=3.10"

# Derive the minimum major/minor actually required (drives the comparison below).
REQ_VERSION=$(echo "$PYTHON_REQ" | grep -oE '[0-9]+\.[0-9]+' | head -1)
REQ_MAJOR="${REQ_VERSION%%.*}"
REQ_MINOR="${REQ_VERSION#*.}"
[[ "$REQ_MAJOR" =~ ^[0-9]+$ ]] || REQ_MAJOR=3
[[ "$REQ_MINOR" =~ ^[0-9]+$ ]] || REQ_MINOR=10

echo -e "${GREEN}✓ Project requires: Python ${PYTHON_REQ}${NC}\n"

# ============================================================================
# Step 2: Find all available Python versions
# ============================================================================

echo -e "${YELLOW}[2/5] Scanning for available Python versions...${NC}"

find_python_versions() {
    local pythons=()

    # Common locations to search (globs are expanded below via nullglob)
    local search_paths=(
        "/usr/bin"
        "/usr/local/bin"
        "/opt/homebrew/bin"
        "/opt/python*/bin"
        "$HOME/.pyenv/versions/*/bin"
        "/usr/local/opt/python*/bin"
    )

    # Expand glob patterns; a pattern that matches nothing disappears.
    shopt -s nullglob
    local pattern dir python_exe base
    for pattern in "${search_paths[@]}"; do
        for dir in $pattern; do
            [ -d "$dir" ] || continue
            while IFS= read -r python_exe; do
                base=$(basename "$python_exe")
                # Only real interpreters: pythonX / pythonX.Y.
                # Rejects python3-config, python3.12-gdb, etc.
                if [[ -x "$python_exe" ]] && [[ "$base" =~ ^python[0-9]+(\.[0-9]+)?$ ]]; then
                    pythons+=("$python_exe")
                fi
            done < <(find "$dir" -maxdepth 1 -name "python*" 2>/dev/null)
        done
    done
    shopt -u nullglob

    # Also check via which/command for well-known versioned names
    local v
    for v in 3.14 3.13 3.12 3.11 3.10 3.9 3.8; do
        if command -v "python${v}" &>/dev/null; then
            pythons+=("$(command -v "python${v}")")
        fi
    done

    # Nothing found: return empty (do not emit a stray blank line)
    if [ ${#pythons[@]} -eq 0 ]; then
        return 0
    fi

    # Remove duplicates
    printf '%s\n' "${pythons[@]}" | sort -u
}

FOUND_PYTHONS=$(find_python_versions)

if [ -z "$FOUND_PYTHONS" ]; then
    echo -e "${RED}ERROR: No Python installations found${NC}"
    exit 1
fi

echo -e "${GREEN}Found the following Python installations:${NC}"

declare -a PYTHON_ARRAY
declare -a SUITABLE_PYTHONS

# Track the highest-version suitable interpreter (by version, not path order).
BEST_KEY=""
BEST_IDX=""

index=0
while IFS= read -r python_exe; do
    if [ -x "$python_exe" ]; then
        version=$("$python_exe" --version 2>&1 | awk '{print $2}')

        # Parse version components
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        patch=$(echo "$version" | cut -d. -f3 | grep -oE '^[0-9]+' || true)
        [ -z "$patch" ] && patch=0

        # Skip anything whose version we could not parse as integers
        # (guards the numeric comparisons below from crashing under set -e).
        if ! [[ "$major" =~ ^[0-9]+$ ]] || ! [[ "$minor" =~ ^[0-9]+$ ]]; then
            continue
        fi

        PYTHON_ARRAY[$index]="$python_exe"

        # Suitable if it meets the requirement parsed from pyproject.toml.
        if [ "$major" -gt "$REQ_MAJOR" ] || \
           { [ "$major" -eq "$REQ_MAJOR" ] && [ "$minor" -ge "$REQ_MINOR" ]; }; then
            echo -e "  ${GREEN}✓${NC} $index) $python_exe (Python $version) ${GREEN}[SUITABLE]${NC}"
            SUITABLE_PYTHONS+=("$index")

            # Zero-padded key so lexical compare == numeric version compare.
            key=$(printf '%03d%03d%03d' "$major" "$minor" "$patch")
            if [[ -z "$BEST_KEY" || "$key" > "$BEST_KEY" ]]; then
                BEST_KEY="$key"
                BEST_IDX="$index"
            fi
        else
            echo -e "  ${RED}✗${NC} $index) $python_exe (Python $version) - TOO OLD (need ${PYTHON_REQ})"
        fi
        index=$((index + 1))
    fi
done <<< "$FOUND_PYTHONS"

if [ ${#SUITABLE_PYTHONS[@]} -eq 0 ]; then
    echo -e "${RED}ERROR: No Python version matching ${PYTHON_REQ} found${NC}"
    echo "Please install Python ${REQ_MAJOR}.${REQ_MINOR} or higher"
    exit 1
fi

echo ""

# ============================================================================
# Step 3: Select Python version (prefer latest)
# ============================================================================

echo -e "${YELLOW}[3/5] Selecting suitable Python version...${NC}"

SELECTED_PYTHON_IDX="$BEST_IDX"  # Highest suitable version (by version number)
SELECTED_PYTHON="${PYTHON_ARRAY[$SELECTED_PYTHON_IDX]}"
SELECTED_VERSION=$("$SELECTED_PYTHON" --version 2>&1 | awk '{print $2}')

echo -e "${GREEN}✓ Selected: $SELECTED_PYTHON (Python $SELECTED_VERSION)${NC}\n"

# ============================================================================
# Step 4: Check required packages
# ============================================================================

echo -e "${YELLOW}[4/5] Checking required packages...${NC}"

check_package() {
    local package=$1
    local python_exe=$2

    if "$python_exe" -c "import $package" 2>/dev/null; then
        return 0  # Package found
    else
        return 1  # Package not found
    fi
}

# Packages required for MCP
REQUIRED_PACKAGES=("mcp")
MISSING_PACKAGES=()

for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if check_package "$pkg" "$SELECTED_PYTHON"; then
        echo -e "  ${GREEN}✓${NC} $pkg is installed"
    else
        echo -e "  ${RED}✗${NC} $pkg is ${RED}NOT${NC} installed"
        MISSING_PACKAGES+=("$pkg")
    fi
done

echo ""

# ============================================================================
# Step 5: Show summary and ask for confirmation
# ============================================================================

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Setup Summary${NC}"
echo -e "${BLUE}================================${NC}\n"

echo -e "Python Selection:"
echo -e "  Executable: ${GREEN}$SELECTED_PYTHON${NC}"
echo -e "  Version:    ${GREEN}$SELECTED_VERSION${NC}"
echo -e "  Requirement: $PYTHON_REQ ${GREEN}✓${NC}"
echo ""

echo -e "Packages to Install:"
if [ ${#MISSING_PACKAGES[@]} -eq 0 ]; then
    echo -e "  ${GREEN}All required packages are installed${NC}"
else
    for pkg in "${MISSING_PACKAGES[@]}"; do
        echo -e "  - ${YELLOW}$pkg${NC}"
    done
fi

echo ""
echo -e "MCP Configuration Files to Update:"
echo -e "  - .vscode/mcp.json"
echo -e "  - .cursor/mcp.json (if exists)"
echo ""

echo -e "Git Ignore Updates:"
echo -e "  - *.backup (config backups this script creates)"
echo ""

# Ask for confirmation
echo -n -e "${YELLOW}Proceed with setup? (yes/no): ${NC}"
read -r confirmation

if [[ "$confirmation" != "yes" && "$confirmation" != "y" ]]; then
    echo -e "${RED}Setup cancelled${NC}"
    exit 0
fi

echo ""

# ============================================================================
# Installation
# ============================================================================

echo -e "${YELLOW}Installing required packages...${NC}"

# pip install that survives PEP 668 "externally-managed-environment" setups
# by falling back to --user and then --break-system-packages.
pip_install() {
    local py=$1 pkg=$2
    if "$py" -m pip install "$pkg"; then
        return 0
    fi
    echo -e "  ${YELLOW}⚠${NC}  Default install failed, retrying with --user..."
    if "$py" -m pip install --user "$pkg"; then
        return 0
    fi
    echo -e "  ${YELLOW}⚠${NC}  Retrying with --break-system-packages..."
    "$py" -m pip install --break-system-packages "$pkg"
}

if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    # Best-effort pip upgrade; never fatal.
    "$SELECTED_PYTHON" -m pip install --upgrade pip || \
        echo -e "  ${YELLOW}⚠${NC}  Could not upgrade pip, continuing..."

    install_failed=0
    for pkg in "${MISSING_PACKAGES[@]}"; do
        echo -e "  Installing ${YELLOW}$pkg${NC}..."
        if ! pip_install "$SELECTED_PYTHON" "$pkg"; then
            echo -e "  ${RED}✗${NC} Failed to install $pkg"
            install_failed=1
        fi
    done

    if [ "$install_failed" -eq 0 ]; then
        echo -e "${GREEN}✓ Packages installed${NC}\n"
    else
        echo -e "${YELLOW}⚠ Some packages failed to install; see messages above${NC}\n"
    fi
else
    echo -e "${GREEN}✓ All packages already installed${NC}\n"
fi

# ============================================================================
# Update MCP Configuration Files
# ============================================================================

echo -e "${YELLOW}Updating MCP configuration files...${NC}"

update_mcp_config() {
    local config_file=$1

    if [ -f "$config_file" ]; then
        # Create backup
        cp "$config_file" "${config_file}.backup"

        # Rewrite the "command" to the explicit interpreter path using Python.
        # Proper JSON handling avoids sed/shell escaping pitfalls with paths
        # that contain spaces or special characters, and it keeps the file
        # valid JSON. Handles both the VSCode ("servers") and Cursor
        # ("mcpServers") schemas.
        if "$SELECTED_PYTHON" - "$config_file" "$SELECTED_PYTHON" <<'PYEOF'
import json, sys
path, newcmd = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except (OSError, ValueError) as e:
    sys.stderr.write("could not read/parse %s: %s\n" % (path, e))
    sys.exit(1)
for key in ("servers", "mcpServers"):
    section = data.get(key)
    if isinstance(section, dict):
        for srv in section.values():
            if isinstance(srv, dict) and "command" in srv:
                srv["command"] = newcmd
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PYEOF
        then
            echo -e "  ${GREEN}✓${NC} Updated $config_file"
            echo -e "     Backup saved: ${config_file}.backup"
        else
            # Restore original on failure so we never leave a broken config
            cp "${config_file}.backup" "$config_file"
            echo -e "  ${RED}✗${NC} Failed to update $config_file (restored from backup)"
        fi
    fi
}

update_mcp_config "$PROJECT_ROOT/.vscode/mcp.json"

if [ -d "$PROJECT_ROOT/.cursor" ]; then
    update_mcp_config "$PROJECT_ROOT/.cursor/mcp.json"
fi

echo ""

# ============================================================================
# Update .gitignore
# ============================================================================

echo -e "${YELLOW}Updating .gitignore...${NC}"

GITIGNORE="$PROJECT_ROOT/.gitignore"
[ -f "$GITIGNORE" ] || touch "$GITIGNORE"

# Ignore the config backups this script creates (*.backup).
# -F: fixed string, so the '.' and '*' are matched literally.
if ! grep -qF "*.backup" "$GITIGNORE"; then
    echo "" >> "$GITIGNORE"
    echo "# MCP config backups (auto-generated by setup-env.sh)" >> "$GITIGNORE"
    echo "*.backup" >> "$GITIGNORE"
    echo -e "  ${GREEN}✓${NC} Added *.backup to .gitignore"
else
    echo -e "  ${GREEN}✓${NC} *.backup already in .gitignore"
fi

echo ""

# ============================================================================
# Verification
# ============================================================================

echo -e "${YELLOW}Verifying setup...${NC}"

# Test MCP import (tolerate a package that exposes no __version__)
if "$SELECTED_PYTHON" -c "import mcp; print('MCP version:', getattr(mcp, '__version__', 'unknown'))" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} MCP is working correctly"
    MCP_OK=1
else
    echo -e "  ${YELLOW}⚠${NC}  MCP import test failed"
    MCP_OK=0
fi

echo ""

# ============================================================================
# Final Summary
# ============================================================================

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}================================${NC}\n"

echo -e "Your environment is ready:"
echo -e "  Python: ${GREEN}$SELECTED_PYTHON${NC} (v$SELECTED_VERSION)"
if [ "${MCP_OK:-0}" -eq 1 ]; then
    echo -e "  MCP: ${GREEN}installed${NC}"
else
    echo -e "  MCP: ${YELLOW}not verified (see warning above)${NC}"
fi
echo -e "  Config: ${GREEN}updated${NC}"
echo ""

echo "Next steps:"
echo "  1. Restart your editor (VSCode/Cursor)"
echo "  2. Smoke-test the MCP server:"
echo "       $SELECTED_PYTHON -m k8smatrixwarden mcp"
echo "  3. Confirm the editor's MCP panel lists 'k8smatrixwarden'"
echo ""

echo -e "${YELLOW}Optional: Remove config backups${NC}"
echo "  rm -f .vscode/mcp.json.backup .cursor/mcp.json.backup"
