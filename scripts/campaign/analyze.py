"""Campaign analysis: per-run table, per-target summary, campaign-level estimates, costs, ablations.

Usage:
  python scripts/campaign/analyze.py --arm full=outputs/campaign [--arm lambda0=outputs/campaign_lambda0]
         [--report campaign/analysis] [--price-input X --price-cached Y --price-output Z]   (USD per 1M tokens)
Writes runs.csv, per_target.csv, summary.md to --report. Definitions: utils/analysis.py docstring.
The mixed-effects model needs statsmodels (optional; skipped with a note if missing).
"""
import argparse
import csv
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from utils.analysis import a12, hier_bootstrap_median, load_runs, median_iqr, rel_improvement  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--arm", action="append", default=None, help="name=dir (repeatable); default full=outputs/campaign")
ap.add_argument("--report", default="outputs/analysis")
ap.add_argument("--price-input", type=float, default=None)
ap.add_argument("--price-cached", type=float, default=None)
ap.add_argument("--price-output", type=float, default=None)
args = ap.parse_args()

arms = dict(a.split("=", 1) for a in (args.arm or ["full=outputs/campaign"]))
rows = [r for name, d in arms.items() for r in load_runs(Path(d), name)]
report = Path(args.report)
report.mkdir(parents=True, exist_ok=True)
if not rows:
    sys.exit("no completed + evaluated runs found")

with (report / "runs.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)

MEASURED = ("OK", "NO_COVERAGE", "CRASHED_EMPTY")   # CRASHED_EMPTY = crashed, no corpus kept: 0 covered
arm_counts = ", ".join(f"{a}: {sum(1 for r in rows if r['arm'] == a)}" for a in arms)
lines = ["# Campaign analysis", "", f"runs: {len(rows)} ({arm_counts})", ""]

# ---- per target, per arm: gen0_best vs final_best -----------------------------------------
per_target_rows, improvements = [], {}
VARIANTS = [("final", "final best")]
if any(r["nobonus_status"] for r in rows):
    VARIANTS.append(("nobonus", "final best without crash bonus (post-hoc)"))
for arm, (var, title) in [(a, v) for a in arms for v in VARIANTS]:
    lines += [f"## Arm `{arm}`: {title} vs. generation-0 best (covered branches)", "",
              "| target | runs | gen0 median [IQR] | final median [IQR] | branches in scope gen0 / final (median) | "
              "improvement median | A12(final,gen0) | final>gen0 / = / < |",
              "|---|---|---|---|---|---|---|---|"]
    improvements[(arm, var)] = {}
    for project in sorted({r["project"] for r in rows if r["arm"] == arm}):
        rs = [r for r in rows if r["arm"] == arm and r["project"] == project
              and r["gen0_status"] in MEASURED and r[f"{var}_status"] in MEASURED]
        g0 = [r["gen0_covered"] for r in rs]
        fb = [r[f"{var}_covered"] for r in rs]
        t0, tf = median_iqr([r["gen0_total"] for r in rs])[0], median_iqr([r[f"{var}_total"] for r in rs])[0]
        imp = [x for x in (rel_improvement(r["gen0_covered"], r[f"{var}_covered"]) for r in rs) if x is not None]
        improvements[(arm, var)][project] = imp
        (gm, g1, g3), (fm, f1, f3), (im, _, _) = median_iqr(g0), median_iqr(fb), median_iqr(imp)
        eff = a12(fb, g0)
        signs = (sum(f > g for f, g in zip(fb, g0)), sum(f == g for f, g in zip(fb, g0)), sum(f < g for f, g in zip(fb, g0)))
        fmt = lambda v: "-" if v is None else f"{v:.2f}"  # noqa: E731
        cnt = lambda v: "-" if v is None else f"{v:g}"  # noqa: E731
        lines.append(f"| {project} | {len(rs)} | {cnt(gm)} [{cnt(g1)}, {cnt(g3)}] | {cnt(fm)} [{cnt(f1)}, {cnt(f3)}] | "
                     f"{cnt(t0)} / {cnt(tf)} | "
                     f"{'-' if im is None else f'{im * 100:+.1f}%'} | {fmt(eff)} | {signs[0]}/{signs[1]}/{signs[2]} |")
        per_target_rows.append({"arm": arm, "variant": var, "target": project, "runs": len(rs), "gen0_median": gm, "final_median": fm,
                                "improvement_median": im, "a12_final_vs_gen0": eff,
                                "final_gt": signs[0], "eq": signs[1], "final_lt": signs[2]})
    point, lo, hi = hier_bootstrap_median(improvements[(arm, var)])
    no_harness = sum(1 for r in rows if r["arm"] == arm and r["no_compiled_initial_harness"])
    unmeasured = sum(1 for r in rows if r["arm"] == arm and not r["no_compiled_initial_harness"]
                     and not (r["gen0_status"] in MEASURED and r[f"{var}_status"] in MEASURED))
    lines += ["", f"Campaign improvement (median of target medians): "
              + ("-" if point is None else f"{point * 100:+.1f}% (95% hierarchical bootstrap CI {lo * 100:+.1f}% .. {hi * 100:+.1f}%)"),
              f"Runs excluded because no initial harness compiled (no evolution possible): {no_harness}",
              f"Runs excluded because a coverage measurement failed (status not OK/NO_COVERAGE/CRASHED_EMPTY): {unmeasured}",
              f"Runs where a harness crashed and kept no corpus input (counted as 0 covered): "
              f"{sum(1 for r in rows if r['arm'] == arm and 'CRASHED_EMPTY' in (r['gen0_status'], r[f'{var}_status']))}", ""]

with (report / "per_target.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(per_target_rows[0]))
    w.writeheader()
    w.writerows(per_target_rows)

# ---- mixed-effects model: log(1 + covered) ~ variant, random intercept target, run nested in target ----
try:
    import pandas as pd
    import statsmodels.formula.api as smf
    for arm in arms:
        long = []
        for r in rows:
            if r["arm"] == arm and r["gen0_status"] in MEASURED and r["final_status"] in MEASURED:
                long += [{"target": r["project"], "run": f"{r['project']}_{r['rep']}", "variant": v,
                          "y": math.log1p(r[f"{v}_covered"])} for v in ("gen0", "final")]
        df = pd.DataFrame(long)
        model = smf.mixedlm("y ~ C(variant, Treatment('gen0'))", df, groups=df["target"],
                            vc_formula={"run": "0 + C(run)"}).fit(reml=True)
        name = [p for p in model.params.index if "variant" in p][0]
        ci = model.conf_int().loc[name]
        lines += [f"Mixed model (`{arm}`, log(1 + covered branches)): final / gen0 = x{math.exp(model.params[name]):.3f} "
                  f"(95% CI x{math.exp(ci[0]):.3f} .. x{math.exp(ci[1]):.3f}, p = {model.pvalues[name]:.4f}); "
                  f"groups: {df['target'].nunique()} targets, {df['run'].nunique()} runs", ""]
except ImportError as exc:
    lines += [f"Mixed model skipped: {exc} (pip install statsmodels)", ""]
except Exception as exc:  # e.g. too few targets for the variance components
    lines += [f"Mixed model failed: {type(exc).__name__}: {exc}", ""]

# ---- ablation: final best of each arm vs. full, same targets ----------------------------------
if "full" in arms and len(arms) > 1:
    lines += ["## Ablations: per-run improvement over the run's own gen-0 best (A12 = P(full > arm))", "",
              "| arm | target | runs full / arm | improvement median full | improvement median arm | A12 |",
              "|---|---|---|---|---|---|"]
    pct = lambda v: "-" if v is None else f"{v * 100:+.1f}%"  # noqa: E731
    for arm in [a for a in arms if a != "full"]:
        for project in sorted({r["project"] for r in rows if r["arm"] == arm}):
            ia, ix = ([x for x in (rel_improvement(r["gen0_covered"], r["final_covered"]) for r in rows
                                   if r["arm"] == a and r["project"] == project
                                   and r["gen0_status"] in MEASURED and r["final_status"] in MEASURED) if x is not None]
                      for a in ("full", arm))
            v = a12(ia, ix)
            lines.append(f"| {arm} | {project} | {len(ia)} / {len(ix)} | {pct(median_iqr(ia)[0])} | {pct(median_iqr(ix)[0])} | "
                         f"{'-' if v is None else f'{v:.2f}'} |")
    lines.append("")

# ---- cost, time, crashes, strategy rules ---------------------------------------------------------
def med(key, arm):
    m, q1, q3 = median_iqr([r[key] for r in rows if r["arm"] == arm and r[key] is not None])
    return "-" if m is None else f"{m:,.0f} [{q1:,.0f}, {q3:,.0f}]"


lines += ["## Cost and time per run (median [IQR])", "", "| arm | LLM requests | prompt tok | cached tok | completion tok | "
          "initial gen s | initial eval s | evolution s |", "|---|---|---|---|---|---|---|---|"]
for arm in arms:
    lines.append(f"| {arm} | {med('llm_requests', arm)} | {med('prompt_tokens', arm)} | {med('cached_prompt_tokens', arm)} | "
                 f"{med('completion_tokens', arm)} | {med('secs_initial_generation', arm)} | "
                 f"{med('secs_initial_evaluation', arm)} | {med('secs_evolution', arm)} |")
if None not in (args.price_input, args.price_cached, args.price_output):
    for arm in arms:
        rs = [r for r in rows if r["arm"] == arm]
        usd = sum(((r["prompt_tokens"] - r["cached_prompt_tokens"]) * args.price_input + r["cached_prompt_tokens"] * args.price_cached
                   + r["completion_tokens"] * args.price_output) / 1e6 for r in rs)
        lines.append(f"\nLLM cost `{arm}`: ${usd:.2f} total, ${usd / len(rs):.3f} per run (prices given on the command line)")
lines += ["", "## Crashes and strategy rules (sums over runs)", "",
          "| arm | runs w/ library crash | library-crash genomes | harness-failure genomes | bonus changed top genome (runs) | "
          "final best has library crash (runs) | final best == recomputed top (runs) | "
          "rule low_stability / path_plateau / uniform / random | usage missing |", "|---|---|---|---|---|---|---|---|---|"]
for arm in arms:
    rs = [r for r in rows if r["arm"] == arm]
    lines.append(f"| {arm} | {sum(1 for r in rs if r['library_crash_genomes'])} | {sum(r['library_crash_genomes'] for r in rs)} | "
                 f"{sum(r['harness_failure_genomes'] for r in rs)} | {sum(1 for r in rs if r['bonus_changed_top'])} | "
                 f"{sum(1 for r in rs if r['final_has_library_crash'])} | "
                 f"{sum(1 for r in rs if r['final_matches_recomputed_top'])}/{len(rs)} | "
                 f"{sum(r['rule_low_stability'] for r in rs)} / {sum(r['rule_path_plateau'] for r in rs)} / "
                 f"{sum(r['rule_uniform'] for r in rs)} / {sum(r['rule_random'] for r in rs)} | {sum(r['usage_missing'] for r in rs)} |")

(report / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
print(f"\nwritten: {report}/runs.csv, per_target.csv, summary.md")
