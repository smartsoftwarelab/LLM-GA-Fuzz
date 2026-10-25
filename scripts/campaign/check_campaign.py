"""Gates (run on the first finished runs before letting the campaign continue, and again at the end).

G1/G2 hand-derived coverage reference passed, deterministic (scripts/p02_coverage_reference.sh output)
G3 usage_log.jsonl lines == HTTP requests seen by httpx (per run audit file)
G4 every generated harness saved and non-empty; lost initial attempts listed
G5 no API key in any output
G6 no run aborted (recursion limit or otherwise)
G7 one clean code commit across runs; G8 one base-image id across runs
Usage: python scripts/campaign/check_campaign.py [--out outputs/campaign] [--reference campaign/preflight_reference.txt]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from utils.campaign import count_http_posts, files_with_secrets  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--out", default="outputs/campaign")
ap.add_argument("--reference", default="campaign/preflight_reference.txt")
ap.add_argument("--final", action="store_true", help="treat runs still marked running as aborted")
args = ap.parse_args()
out = Path(args.out)

gates: list[tuple[str, bool, str]] = []
ref = Path(args.reference).read_text() if Path(args.reference).exists() else ""
gates.append(("G1 coverage == hand-derived reference", "PASS  A branches == 4/6" in ref and "OVERALL: PASS" in ref, args.reference))
gates.append(("G2 three identical measurements", "PASS  A determinism" in ref, args.reference))

manifests = sorted(out.glob("rep*/*/*/run_manifest.json"))
commits, images, lost, aborted, g3_bad, g4_bad, running, no_ids = set(), set(), [], [], [], [], [], []
for mp in manifests:
    m = json.loads(mp.read_text())
    d = mp.parent
    key = f"{m['project']}_rep{m['repetition_index']}"
    if m["status"] == "running" and not args.final:
        running.append(key)          # in progress: no end-of-run fields yet, checked once finished
        continue
    commits.add((m["code"].get("commit"), m["code"].get("dirty")))
    ids = {k: v.get("id") for k, v in m.get("docker_images_end", {}).items()}
    images.add(json.dumps(ids, sort_keys=True))
    if not ids or None in ids.values():          # an unrecorded image id must not pass as "one id"
        no_ids.append(key)
    if m["status"] != "completed":
        aborted.append(f"{key}:{m['status']}")
    for a in m.get("initial_attempts", []):
        if a["status"] != "OK":
            lost.append(f"{key}#{a['index']}:{a['status']}:{(a.get('error') or '')[:60]}")
    lines = sum(1 for _ in (d / "usage_log.jsonl").open()) if (d / "usage_log.jsonl").exists() else 0
    posts = count_http_posts(out / "audit" / f"{key}.log")
    if posts != lines:
        g3_bad.append(f"{key}: usage={lines} http={posts}")
    for g in d.glob("evolution/gen_*/*.json"):
        gj = json.loads(g.read_text(encoding="utf-8"))
        if not gj.get("code", "").strip():
            g4_bad.append(str(g))

gates.append(("G3 usage lines == HTTP requests", bool(manifests) and not g3_bad, "; ".join(g3_bad) or f"{len(manifests)} runs"))
gates.append(("G4 harnesses saved and non-empty", not g4_bad, f"empty={len(g4_bad)} lost_initial_attempts={len(lost)}"))
secrets = files_with_secrets(out)
gates.append(("G5 no API key in outputs", not secrets, "; ".join(secrets[:5])))
gates.append(("G6 no aborted run", not aborted, "; ".join(aborted)))
gates.append(("G7 single clean code commit", len(commits) == 1 and not next(iter(commits))[1] if commits else False, str(commits)))
gates.append(("G8 single base-image id", len(images) == 1 and not no_ids,
              f"{len(images)} distinct; id not recorded: {no_ids or 'none'}"))

for name, ok, detail in gates:
    print(f"{'PASS' if ok else 'FAIL'}  {name}  [{detail}]")
if lost:
    print("lost initial attempts (recorded, not fatal):")
    for x in lost:
        print("  " + x)
print(f"runs checked: {len(manifests) - len(running)}  in progress (skipped): {running or 'none'}")
print("OVERALL:", "PASS" if all(ok for _, ok, _ in gates) else "FAIL")
