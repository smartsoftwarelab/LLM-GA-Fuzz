from agent_tools.code_retriever import CodeRetriever
from agent.modules.compilation import  CompilerWraper
from constants import LanguageType
from typing import Any
import logging

from pathlib import Path


class HeaderCompilerWraper(CompilerWraper):
    def __init__(self, oss_fuzz_dir: Path, project_name: str, new_project_name: str, code_retriever: CodeRetriever,
                     project_lang: LanguageType, harness_dict:dict[str, Path], 
                     save_dir: Path, cache_dir: Path, logger: logging.Logger):
        super().__init__(oss_fuzz_dir, project_name, new_project_name, code_retriever, project_lang, harness_dict, save_dir, cache_dir, logger)

    def compile_harness(self, state: dict[str, Any]) -> dict[str, Any]: # type: ignore
        '''
        Compile the harness code with the header files.
        '''
        # get the harness code
        harness_code: str = state["harness_code"] # type: ignore
        # get the header files
        header_files = self.code_retriever.get_all_headers()
        if len(header_files) == 0:
            self.logger.warning("No header files found, use empty string")
            header_files = ""
        else:
            header_files = "\n".join([f'#include "{h}"' for h in header_files])

        # add the header files to the harness code
        new_harness_code = f"{header_files}\n\n{harness_code}"
        
        # add all headers to the state, this will not replace the existing harness code
        state["harness_code"] = new_harness_code
        return super().compile_harness(state) # type: ignore
