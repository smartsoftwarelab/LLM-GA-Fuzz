#!/bin/bash
# ============================================================
# Full Campaign Analysis Script — LLM-Reasoning-Agents Fuzzer
# Run this on Ubuntu where the oss-fuzz binaries are available
# ============================================================

OUTPUTS_DIR="/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs"
BUILD_DIR="/home/ubuntu/fuzzing_workspace/oss-fuzz/build/out"
REPORT_FILE="/tmp/fuzzing_campaign_report.md"

# ── colour helpers ──────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

# ── find binary that contains a given function symbol ───────
find_binary_for_function() {
    local func="$1"
    for dir in "$BUILD_DIR"/*/; do
        for bin in "$dir"*; do
            [ -f "$bin" ] && [ -x "$bin" ] || continue
            if llvm-nm "$bin" 2>/dev/null | grep -qi " $func$"; then
                echo "$bin"
                return 0
            fi
        done
    done
    return 1
}

# ── count CFG edges for a list of functions in a binary ─────
count_edges() {
    local binary="$1"
    shift
    local funcs=("$@")

    python3 -c "
import sys, re

TARGET_FUNCS = $(python3 -c "import sys; print(repr(sys.argv[1:]))" "${funcs[@]}")

branch_re = re.compile(r'\s+j[a-z]{1,5}\s')
ret_re    = re.compile(r'\s+ret')
hdr_re    = re.compile(r'^[0-9a-f]+ <(.+?)>:')

inside, cur, results = False, None, {}

for line in sys.stdin:
    m = hdr_re.match(line)
    if m:
        cur    = m.group(1)
        inside = cur in TARGET_FUNCS
        if inside:
            results.setdefault(cur, 0)
        continue
    if inside and (branch_re.search(line) or ret_re.search(line)):
        results[cur] += 1

total = sum(results.values())
print(total)
" < <(llvm-objdump -d "$binary" 2>/dev/null)
}

# ── extract last value of a key from generation_stats.json ──
jq_last() {
    local file="$1" key="$2"
    python3 -c "
import json, sys
data = json.load(open('$file'))
last = data[-1]
print(last.get('$key', 'N/A'))
"
}

jq_max() {
    local file="$1" key="$2"
    python3 -c "
import json
data = json.load(open('$file'))
vals = [g.get('$key', 0) for g in data]
print(max(vals))
"
}

# ── total binary edges from a fuzzing log ───────────────────
get_total_binary_edges() {
    local log_dir="$1"
    grep -h "inline 8-bit counters" "$log_dir"/**/fuzzing*.log 2>/dev/null \
        | grep -oP '\(\K[0-9]+(?= inline)' | sort -n | tail -1
}

# ============================================================
# Campaign definitions: "campaign_dir|library|target_func|callees..."
# callees = space-separated function names reachable from target
# ============================================================
declare -A CAMPAIGNS

CAMPAIGNS["ada-url"]="evo_ada-url_ok|ada-url|ada_parse_with_base|ada_parse ada_free ada_get_href ada_get_pathname ada_get_search ada_get_hostname"
CAMPAIGNS["cjson"]="evo_cjson_|cjson|cJSON_PrintPreallocated|cJSON_PrintPreallocated cJSON_Print cJSON_PrintBuffered cJSON_PrintUnformatted cJSON_malloc cJSON_free cJSON_Parse cJSON_Delete"
CAMPAIGNS["freerdp"]="evo_freerdp|freerdp|client_auto_reconnect|client_auto_reconnect freerdp_connect freerdp_get_last_connect_error"
CAMPAIGNS["libtsm"]="evo_libtsm|libtsm|tsm_vte_set_palette|tsm_vte_set_palette tsm_screen_new tsm_vte_new"
CAMPAIGNS["pjsip"]="evo_pjsip|pjsip|pjsip_endpt_send_raw_to_uri|pjsip_endpt_send_raw_to_uri pjsip_endpt_create pj_pool_create"
CAMPAIGNS["plan9port"]="evo_plan9port|plan9port|BINARY_MISSING_USE_LOG|SKIP"
# plan9port: binary was cleaned up. Total edges from fuzzing logs = 1527 (binary-scoped)
# archive_best_cov=225, edge_coverage%=225/1527=14.7%
CAMPAIGNS["gpac"]="evo_gpac|gpac|visual_2d_draw_frame|visual_2d_draw_frame visual_2d_setup_projection visual_2d_init_draw visual_2d_terminate_draw visual_2d_init_raster visual_2d_release_raster visual_clean_contexts gf_evg_surface_new gf_evg_surface_delete gf_list_count gf_list_get gf_list_enum gf_malloc gf_free gf_rect_pixelize gf_cmx_init gf_mx2d_init"

# ============================================================
# Main report generation
# ============================================================
{
echo "# LLM+GA Fuzzing Campaign — Full Analysis Report"
echo "**Generated:** $(date)"
echo ""
echo "---"
echo ""
echo "## Summary Table"
echo ""
echo "| Campaign | Target Function | Gens | Initial Cov | Final Cov | Peak Cov | Crash | Total Edges | Reachable | Coverage% |"
echo "|----------|----------------|------|-------------|-----------|----------|-------|-------------|-----------|-----------|"
} > "$REPORT_FILE"

declare -A RESULTS

for campaign_key in "${!CAMPAIGNS[@]}"; do
    IFS='|' read -r campaign_dir library target_func callees_str <<< "${CAMPAIGNS[$campaign_key]}"
    IFS=' ' read -ra callees <<< "$callees_str"

    log "Processing: $campaign_key → $target_func"

    stats_file=$(find "$OUTPUTS_DIR/$campaign_dir" -name "generation_stats.json" 2>/dev/null | head -1)
    if [ -z "$stats_file" ]; then
        warn "  No generation_stats.json found — skipping"
        continue
    fi

    # Extract stats
    n_gens=$(python3 -c "import json; d=json.load(open('$stats_file')); print(len(d))")
    initial_cov=$(python3 -c "import json; d=json.load(open('$stats_file')); print(d[0].get('archive_best_cov',0))")
    final_cov=$(jq_last "$stats_file" "archive_best_cov")
    peak_cov=$(jq_max "$stats_file" "max_coverage")
    crash=$(jq_last "$stats_file" "crash_found")
    crash_gen=$(python3 -c "
import json
d=json.load(open('$stats_file'))
for i,g in enumerate(d):
    if g.get('crash_found'):
        print(i); exit()
print('N/A')
")

    # Get total binary edges from logs
    log_dir=$(find "$OUTPUTS_DIR/$campaign_dir" -name "fuzzing*.log" 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
    total_edges=$(grep -h "inline 8-bit counters" $(find "$OUTPUTS_DIR/$campaign_dir" -name "fuzzing*.log" 2>/dev/null) 2>/dev/null \
        | grep -oP '\(\K[0-9]+(?= inline)' | sort -n | tail -1)
    [ -z "$total_edges" ] && total_edges="N/A"

    # Find binary and count reachable edges
    log "  Searching for binary containing '$target_func'..."
    binary=$(find_binary_for_function "$target_func")

    if [ -n "$binary" ]; then
        log "  Found binary: $binary"
        reachable_edges=$(count_edges "$binary" "${callees[@]}")
        if [ "$reachable_edges" -gt 0 ] 2>/dev/null; then
            coverage_pct=$(python3 -c "print(f'{$final_cov/$reachable_edges*100:.1f}%')" 2>/dev/null || echo "N/A")
        else
            reachable_edges="N/A"
            coverage_pct="N/A"
        fi
    else
        warn "  Binary not found for $target_func"
        reachable_edges="N/A"
        coverage_pct="N/A"
    fi

    crash_label="No"
    [ "$crash" = "True" ] && crash_label="**Yes** (Gen $crash_gen)"

    # Write to report
    echo "| $campaign_key | \`$target_func\` | $n_gens | $initial_cov | $final_cov | $peak_cov | $crash_label | $total_edges | $reachable_edges | $coverage_pct |" >> "$REPORT_FILE"

    # Store for detailed section
    RESULTS[$campaign_key]="gens=$n_gens|init=$initial_cov|final=$final_cov|peak=$peak_cov|crash=$crash_label|total=$total_edges|reach=$reachable_edges|pct=$coverage_pct|binary=${binary:-NOT_FOUND}"
done

# ── Detailed per-campaign section ───────────────────────────
{
echo ""
echo "---"
echo ""
echo "## Detailed Results Per Campaign"
} >> "$REPORT_FILE"

for campaign_key in "${!CAMPAIGNS[@]}"; do
    IFS='|' read -r campaign_dir library target_func callees_str <<< "${CAMPAIGNS[$campaign_key]}"
    stats_file=$(find "$OUTPUTS_DIR/$campaign_dir" -name "generation_stats.json" 2>/dev/null | head -1)
    [ -z "$stats_file" ] && continue

    IFS='|' read -r gens init_cov final_cov peak_cov crash total reach pct binary_path <<< \
        "$(echo "${RESULTS[$campaign_key]}" | tr '|' '\n' | sed 's/^[^=]*=//' | tr '\n' '|')"

    {
    echo ""
    echo "### $campaign_key — \`$target_func\`"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Library | $library |"
    echo "| Generations run | ${RESULTS[$campaign_key]%%|*} |"
    echo "| Initial coverage | $initial_cov edges |" 2>/dev/null
    echo "| Final archive coverage | $final_cov edges |"
    echo "| Peak coverage | $peak_cov edges |"
    echo "| Crash found | $crash |"
    echo "| Total binary edges | $total |"
    echo "| Reachable edges (callgraph) | $reach |"
    echo "| Edge coverage % (reachable) | $pct |"
    echo ""
    echo "**Generation progression:**"
    echo ""
    echo "\`\`\`"
    python3 -c "
import json
data = json.load(open('$stats_file'))
print(f'{'Gen':>4}  {'Compiled':>8}  {'MaxCov':>7}  {'ArchCov':>7}  {'AvgFit':>8}  {'Crash':>6}')
print('-' * 55)
for g in data:
    crash_marker = '<<' if g.get('crash_found') else ''
    print(f'{g[\"generation\"]:>4}  {g[\"n_compiled\"]:>8}  {g[\"max_coverage\"]:>7}  {g[\"archive_best_cov\"]:>7}  {g[\"avg_fitness\"]:>8.4f}  {str(g[\"crash_found\"]):>6} {crash_marker}')
"
    echo "\`\`\`"
    } >> "$REPORT_FILE"
done

{
echo ""
echo "---"
echo ""
echo "## Cross-Campaign Comparison"
echo ""
echo "### Coverage Improvement"
echo ""
python3 << 'PYEOF'
import json, os, glob

campaigns = {
    "ada-url":    "evo_ada-url_ok",
    "cjson":      "evo_cjson_",
    "freerdp":    "evo_freerdp/freerdp",
    "libtsm":     "evo_libtsm",
    "pjsip":      "evo_pjsip",
    "plan9port":  "evo_plan9port",
    "gpac":       "evo_gpac",
}

base = "/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs"

print("| Campaign | Gen 0 | Final | Improvement |")
print("|----------|-------|-------|-------------|")
for name, d in campaigns.items():
    pattern = os.path.join(base, d, "**", "generation_stats.json")
    files = glob.glob(pattern, recursive=True)
    if not files:
        continue
    data = json.load(open(files[0]))
    if not data:
        continue
    g0  = data[0].get("archive_best_cov", 0) or data[0].get("max_coverage", 0)
    gf  = data[-1].get("archive_best_cov", 0)
    imp = f"+{(gf-g0)/g0*100:.0f}%" if g0 > 0 else "N/A"
    print(f"| {name} | {g0} | {gf} | {imp} |")
PYEOF
} >> "$REPORT_FILE"

echo ""
log "Report written to: $REPORT_FILE"
echo ""
cat "$REPORT_FILE"