#!/bin/bash

# ─────────────────────────────────────────────
#  nmap_scan.sh
#  Reads targets from scope.txt and runs nmap
#  against each one, saving output to ./nmap/
# ─────────────────────────────────────────────

SCOPE_FILE="scope.txt"
OUTPUT_DIR="nmap"
NMAP_FLAGS=(-vvv -sT -sC -O -A -Pn -p- -T5)

# ── Colours ───────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m';    RST='\033[0m'

# ── Preflight checks ──────────────────────────

if ! command -v nmap &>/dev/null; then
    echo -e "${R}[!] nmap is not installed or not in PATH. Aborting.${RST}"
    exit 1
fi

if [[ ! -f "$SCOPE_FILE" ]]; then
    echo -e "${R}[!] Scope file '$SCOPE_FILE' not found. Aborting.${RST}"
    exit 1
fi

# Count only real targets (skip blanks and comments)
TOTAL=$(grep -cE '^[^#[:space:]]' "$SCOPE_FILE" || true)

if [[ "$TOTAL" -eq 0 ]]; then
    echo -e "${R}[!] Scope file '$SCOPE_FILE' has no valid targets. Aborting.${RST}"
    exit 1
fi

# ── Create output directory ───────────────────

mkdir -p "$OUTPUT_DIR"

echo -e "${C}${B}"
echo "  ┌─────────────────────────────────────────┐"
echo "  │           nmap auto-scanner             │"
echo "  └─────────────────────────────────────────┘"
echo -e "${RST}"
echo -e "${G}[*]${RST} Scope file  : ${B}$SCOPE_FILE${RST} (${B}${TOTAL}${RST} targets)"
echo -e "${G}[*]${RST} Output dir  : ${B}$(realpath "$OUTPUT_DIR")${RST}"
echo -e "${G}[*]${RST} nmap flags  : ${B}${NMAP_FLAGS[*]}${RST}"
echo -e "${G}[*]${RST} Started     : $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ── Tracking ──────────────────────────────────

COUNT=0
FAILED=()
SCAN_START=$(date +%s)

# ── Main scan loop ────────────────────────────

while IFS= read -r target || [[ -n "$target" ]]; do

    # Skip blank lines and comments
    [[ -z "$target" || "$target" =~ ^[[:space:]]*# ]] && continue

    # Strip leading/trailing whitespace
    target="${target#"${target%%[![:space:]]*}"}"
    target="${target%"${target##*[![:space:]]}"}"
    [[ -z "$target" ]] && continue

    COUNT=$((COUNT + 1))

    safe_name=$(echo "$target" | tr '/:*?"<>|\\' '_')
    output_file="${OUTPUT_DIR}/${safe_name}"

    echo -e "${C}[${COUNT}/${TOTAL}]${RST} ${B}${target}${RST}"
    echo -e "      Output  : $output_file"
    echo -e "      Started : $(date '+%Y-%m-%d %H:%M:%S')"

    HOST_START=$(date +%s)

    nmap "${NMAP_FLAGS[@]}" -oN "$output_file" "$target"
    EXIT_CODE=$?

    HOST_END=$(date +%s)
    ELAPSED=$(( HOST_END - HOST_START ))
    ELAPSED_FMT=$(printf '%02dh:%02dm:%02ds' \
        $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

    if [[ $EXIT_CODE -eq 0 ]]; then
        echo -e "      Status  : ${G}Done ✓${RST}  (${ELAPSED_FMT})"
    else
        echo -e "      Status  : ${R}nmap exited with code $EXIT_CODE ✗${RST}  (${ELAPSED_FMT})"
        FAILED+=("$target")
    fi

    echo ""

done < "$SCOPE_FILE"

# ── Final summary ─────────────────────────────

SCAN_END=$(date +%s)
TOTAL_ELAPSED=$(( SCAN_END - SCAN_START ))
TOTAL_FMT=$(printf '%02dh:%02dm:%02ds' \
    $((TOTAL_ELAPSED/3600)) $(((TOTAL_ELAPSED%3600)/60)) $((TOTAL_ELAPSED%60)))

echo -e "${B}${C}══════════════════════════════════════════════${RST}"
echo -e "${G}[*]${RST} All scans complete"
echo -e "${G}[*]${RST} Results saved to : ${B}${OUTPUT_DIR}/${RST}"
echo -e "${G}[*]${RST} Targets scanned  : ${B}${COUNT}/${TOTAL}${RST}"
echo -e "${G}[*]${RST} Total time       : ${B}${TOTAL_FMT}${RST}"
echo -e "${G}[*]${RST} Finished         : $(date '+%Y-%m-%d %H:%M:%S')"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo ""
    echo -e "${R}[!] Failed targets (${#FAILED[@]}):${RST}"
    for t in "${FAILED[@]}"; do
        echo -e "    ${R}✗${RST} $t"
    done
fi

echo -e "${B}${C}══════════════════════════════════════════════${RST}"
