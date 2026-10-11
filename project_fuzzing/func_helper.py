import json
from pathlib import Path

def only_in_lsp(lsp_func_path: Path, cov_func_path: Path) -> Path:
    """Diff the functions in two JSON files and return the list of different function signatures."""
    with open(lsp_func_path, 'r') as f:
        lsp_funcs = json.load(f)

    with open(cov_func_path, 'r') as f:
        cov_funcs = json.load(f)

    cov_name_list = [func_info.get("clean_name", "") for func_info in cov_funcs["functions"]]

    diff_funcs: list[str] = []
    for func_info in lsp_funcs:
        func_name = func_info.get("name", "")
        if func_name not in cov_name_list:
            diff_funcs.append(func_info)
      
    save_file = cov_func_path.parent / f"All_all_symbols_lsp.json"
    with open(save_file, 'w') as f:
        json.dump(diff_funcs, f, indent=4)

    return save_file

def filter_functions(lsp_func_path: Path, filter_path_pattern: str) -> None:
    """Filter out functions that are already in the coverage file."""
    with open(lsp_func_path, 'r') as f:
        lsp_funcs = json.load(f)

    filtered_funcs: list[dict[str, str]] = []
    for func_info in lsp_funcs:
        func_path = func_info.get("file_path", "")
        if not func_path.startswith(filter_path_pattern):
            filtered_funcs.append(func_info)
       
      
    with open(lsp_func_path, 'w') as f:
        json.dump(filtered_funcs, f, indent=4)


if __name__ == "__main__":
    lsp_func_path = Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/cache/aa_projects/mosquitto/All_all_symbols_lsp.json")
    cov_func_path = Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/project_fuzzing/projects/mosquitto/functions.json")
    save_file = only_in_lsp(lsp_func_path, cov_func_path)

    filter_functions(save_file, "/src/mosquitto/fuzzing")