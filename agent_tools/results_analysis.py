import os
from constants import EvalResult, LanguageType, PROJECT_PATH
from collections import defaultdict
from agent_tools.code_tools.parsers.cpp_parser import CPPParser
from agent_tools.code_tools.parsers.java_parser import JavaParser 
from utils.misc import extract_name, get_run_path
from pathlib import Path
from typing import DefaultDict
from utils.misc import write_list_to_file
from typing import Any
import json

OSSFUZZ = Path(f"{PROJECT_PATH}/code/oss-fuzz")
benchmark_dir = Path(f"{PROJECT_PATH}/benchmark-sets")

def get_language_info(project_name: str) -> str:

    yaml_file = OSSFUZZ / "projects" / project_name / "project.yaml"
    if yaml_file.exists():
        with open(yaml_file, "r") as f:
            import yaml
            cfg = yaml.safe_load(f)
            lang = cfg.get("language", "none")
            return lang
    return "none"

def get_run_res(work_dir: Path, semantic_mode: str="eval", language: LanguageType=LanguageType.CPP) -> EvalResult:

    work_dir = Path(work_dir)
      # read the agent.log
    log_file = work_dir / "agent.log"
    harness_path = work_dir / "harness.txt"
    func_sig_path = work_dir / "function.txt"

    function_signature = func_sig_path.read_text()
    function_name = extract_name(function_signature, language=language)

    if not log_file.exists():
        return EvalResult.NoLogError

    log_lines = log_file.read_text()
   
    for line in log_lines.split("\n"):
        if "WARNING" in line and "Exit" in line:
            return EvalResult.NoLogError

    # for issta
    if semantic_mode in ["both", "eval"]:
        pass_pattern = "Semantic check passed"
    else:
        pass_pattern = "Fuzz res:No Error"
        
    if pass_pattern not in log_lines:
        return EvalResult.Failed
    
    if semantic_mode == "eval" and "Semantic check failed" in log_lines:
        return EvalResult.Failed

    if language in [LanguageType.CPP, LanguageType.C]:
        parser = CPPParser(file_path=harness_path)
    elif language == LanguageType.JAVA:
        parser = JavaParser(file_path=harness_path)
    else:
        raise NotImplementedError(f"Language {language} not supported yet.")

    if parser.is_function_defined(function_name):
        return EvalResult.Fake
    
    if parser.is_function_called(function_name):
        return EvalResult.Success
    else:
        return EvalResult.NoCall

def collect_run_info(output_path: Path, n_run:int=1, single_run:bool=False) -> tuple[list[tuple[str, str, Path]], list[str], set[str]]:
    build_failed: list[str] = []
    all_projects: set[str] = set()
    all_path:list[tuple[str, str, Path]] = []
    # sort the directory
    for project_path in sorted(output_path.iterdir()):
        if not project_path.is_dir():
            continue
        all_projects.add(project_path.name)

        for function_path in project_path.iterdir():
            if not function_path.is_dir():
                continue

            for work_dir in function_path.iterdir():
                if not work_dir.is_dir():
                    continue
                if not work_dir.exists():
                    continue
               
                # get the run number
                n = int(work_dir.name.split("_")[0][3:])
                if n > n_run:
                    continue
                if single_run and n != n_run:
                    continue

                # check if the directory is empty
                if len(os.listdir(work_dir)) <= 4:
                    build_failed.append(f"{project_path.name}/{function_path.name}")
                    continue
                func_sig_path = work_dir / "function.txt"
                if not func_sig_path.exists():
                    build_failed.append(f"{project_path.name}/{function_path.name}")
                    continue
                func_sig = func_sig_path.read_text().strip()

                all_path.append((project_path.name, func_sig, work_dir))

    return all_path, build_failed, all_projects

def run_agent_res(output_path: Path, semantic_mode:str, n_run:int=1, language: LanguageType=LanguageType.CPP): 

    res_count: DefaultDict[str, int] = defaultdict(int)
    lang_count: DefaultDict[str, int] = defaultdict(int)
    output_path = Path(output_path)
    success_json:dict[str, Any] = {}

    res_file = output_path / f"res_{n_run}.txt"
    
    # save the projects whose functions are all failed
    all_path, build_failed, all_projects = collect_run_info(output_path, n_run=n_run)
    
    # collect results first
    results_list: list[tuple[str, str, EvalResult]] = []
    for project_name, func_sig, work_dir in all_path:

        # get language info
        function_name = extract_name(func_sig, keep_namespace=True, language=language)
        eval_res = get_run_res(work_dir, semantic_mode=semantic_mode, language=language)

        if eval_res != EvalResult.Success:
            res_count[eval_res.value] += 1
            results_list.append((project_name, function_name, eval_res))
            continue

        if project_name in all_projects:
            all_projects.remove(project_name)
        
        #  only count once
        res_count[eval_res.value] += 1

        func_dict = {
            "project": project_name,
            "work_dir": str(work_dir),
        }

        success_json[project_name+ "+" + func_sig] = func_dict

        # get language info
        lang = get_language_info(project_name)
        lang_count[lang] += 1
        results_list.append((project_name, function_name, eval_res))
    
    # sort results by project_name then function_name
    results_list.sort(key=lambda x: (x[0], x[1]))
    
    # save sorted results to file
    with open(res_file, "w") as save_f:
        for project_name, function_name, eval_res in results_list:
            save_f.write(f"{project_name}/{function_name}. fuzz res: {eval_res}\n")
        
        save_f.write(f"Results count: {res_count}\n")
        save_f.write(f"Success:{res_count[EvalResult.Success.value] }\n")
        save_f.write(f"Language success count: {lang_count}\n")

    all_projects = sorted(list(all_projects))
    write_list_to_file(all_projects, output_path / f"failed_projects_{n_run}.txt")
    write_list_to_file(build_failed, output_path / f"build_failed_functions_{n_run}.txt")
    # json dump
    with open(output_path / f"success_functions_{n_run}.json", "w") as f:
            json.dump(success_json, f, indent=4)


def get_evaluation_results(eval_path: Path) -> dict[str, int]:
    """Summarise evaluation_results*.json written by agent.eval.run_evaluation.

    Counts records per coverage status; statistics use measured results only
    (status OK / NO_COVERAGE). Failures are counted, never averaged in as 0.
    """
    files = sorted(eval_path.glob("evaluation_results*.json"))
    if not files:
        raise FileNotFoundError(f"no evaluation_results*.json in {eval_path}")

    records: dict[str, Any] = {}
    for res_file in files:
        data = json.loads(res_file.read_text())
        for key, rec in data.items():
            if not isinstance(rec, dict) or "coverage" not in rec:
                raise ValueError(f"{res_file}: legacy entry for {key!r} (pre-llvm-cov format); re-run agent.eval")
            records[key] = rec

    status_counts: dict[str, int] = defaultdict(int)
    for rec in records.values():
        status_counts[rec["coverage"]["status"]] += 1
    measured = [rec["coverage"] for rec in records.values() if rec["coverage"]["status"] in ("OK", "NO_COVERAGE")]

    print(f"Total evaluated functions: {len(records)}")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")
    if measured:
        metric = measured[0]["metric"]
        mean_pct = sum(c["percent"] for c in measured) / len(measured)
        print(f"Mean {metric} coverage over {len(measured)} measured functions: {mean_pct:.2f}%")
    crashed = sum(1 for rec in records.values() if rec.get("fuzz_result") == "Crash")
    print(f"Fuzzing runs that reported a crash: {crashed}")
    return dict(status_counts)

if __name__ == "__main__":

    # eval_res = get_run_res(Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs_wild/gpt5-mini/agent/mupdf/pdf_save_document/run3_qurmgvgmdbtazfza"), 
                        #    semantic_mode="eval")
    # print(f"Evaluation result: {eval_res}")
    # get_evaluation_results(Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs_evaluation/gpt5-mini/agent"))
    # get_evaluation_results(Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs_evaluation/gpt5-mini/raw"))
    # get_evaluation_results(Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs/projects/evaluation/gpt5-mini/net-snmp"))
    run_agent_res(Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs/java/gpt5-mini/agent"), semantic_mode="gen", n_run=1, language=LanguageType.JAVA)
    # run_oss_fuzz_res()

