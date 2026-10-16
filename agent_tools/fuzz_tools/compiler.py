import json
import time
from datetime import datetime, timezone
from utils.oss_fuzz_utils import OSSFuzzUtils
from utils.docker_utils import DockerUtils
from constants import CompileResults
from utils.misc import save_code_to_file, remove_color_characters, kill_process
import subprocess as sp
import os
import shutil
from pathlib import Path
from typing import Optional
import random

def record_build_timing(project: str, sanitizer: Optional[str], image_s: Optional[float],
                        total_s: float, result: CompileResults) -> None:
    """Append one JSON line per compile to $LLMGA_BUILD_TIMINGS (no-op when unset)."""
    path = os.environ.get("LLMGA_BUILD_TIMINGS")
    if not path:
        return
    rec = {"timestamp": datetime.now(timezone.utc).isoformat(), "pid": os.getpid(), "project": project,
           "sanitizer": sanitizer or "default", "result": result.name,
           "build_image_s": None if image_s is None else round(image_s, 1),
           "build_fuzzers_s": None if image_s is None else round(total_s - image_s, 1),
           "total_s": round(total_s, 1)}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


class Compiler():

    def __init__(self, oss_fuzz_dir: Path, benchmark_dir: Path, project_name: str, new_project_name: str, include_path: Optional[set[str]]=None,
                 sanitizer: Optional[str]=None):

        self.oss_fuzz_dir = oss_fuzz_dir
        self.project_name = project_name
        self.new_project_name = new_project_name
       
        self.oss_tool = OSSFuzzUtils(oss_fuzz_dir, benchmark_dir, project_name, new_project_name)
        self.project_lang =  self.oss_tool.get_project_language()
        self.docker_tool = DockerUtils(oss_fuzz_dir, project_name, new_project_name, self.project_lang)

        self.sanitizer = sanitizer
        self.build_harness_cmd = self.oss_tool.get_script_cmd("build_fuzzers")
        if sanitizer:
            # helper.py build_fuzzers --clean --sanitizer=<sanitizer> <project>
            self.build_harness_cmd = self.build_harness_cmd[:-1] + [f"--sanitizer={sanitizer}", self.build_harness_cmd[-1]]

        # self.build_harness_cmd = ["python", os.path.join(self.oss_fuzz_dir, "infra", "helper.py"),
                            # "build_fuzzers", "--clean", self.new_project_name,  "--", "-fsanitize=fuzzer", "-fsanitize=address", "-fsanitize-coverage=trace-pc-guard"]
        self.build_image_cmd =  self.oss_tool.get_script_cmd("build_image")
        self.include_path: set[str] = include_path if include_path else set()


    def write_dockerfile(self, harness_code: str, harness_path: Path, cmd: Optional[str]=None) -> None:
        '''Copy the harness file to overwrite all existing harness files'''
        # write copy in dockerfile and re-build the image

        docker_file_path = self.oss_fuzz_dir / "projects" / self.new_project_name / 'Dockerfile'
        docker_file_bak = docker_file_path.with_suffix('.bak')

        
        # resotre the old dockerfile
        if docker_file_bak.exists():
            shutil.copy(docker_file_bak, docker_file_path)
        else:
            shutil.copy(docker_file_path, docker_file_bak)

        
        # save the target to the project, generate a random name to prevent caching
        random_str = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=16))
        new_local_name = f"{harness_path.stem}_{random_str}{harness_path.suffix}"
        local_harness_path = self.oss_fuzz_dir / "projects" / self.new_project_name / new_local_name
        save_code_to_file(harness_code, local_harness_path)
        
        # for other files in the project that may include the harness file, we also need to overwrite them
        original_harness_path = self.oss_fuzz_dir / "projects" / self.new_project_name / harness_path.name
        save_code_to_file(harness_code, original_harness_path)

        with open(docker_file_path, 'a') as f:
            # Add additional statement in dockerfile to overwrite with generated fuzzer
            f.write(f'\nCOPY {new_local_name} {harness_path}\n')

            if cmd:
                f.write(f'{cmd}\n')

    def write_build_script(self) -> None:
        '''Copy the harness file to overwrite all existing harness files'''
        # write copy in build.sh and re-build the image
        if not self.include_path:
            return
    
        build_script_path = self.oss_fuzz_dir / "projects" / self.new_project_name / 'build.sh'
        build_script_bak = build_script_path.with_suffix('.bak')

        # resotre the old build script
        if build_script_bak.exists():
            shutil.copy(build_script_bak, build_script_path)
        else:
            shutil.copy(build_script_path, build_script_bak)

        # insert the export CFLAGS after the first line
        all_lines = build_script_path.read_text().splitlines()

        include_flags = ' '.join([f'-I{path}' for path in self.include_path])
        all_lines.insert(1, f'export CFLAGS="$CFLAGS {include_flags}"')
        all_lines.insert(2, f'export CXXFLAGS="$CXXFLAGS {include_flags}"')
        
        with open(build_script_path, 'w') as f:
            f.writelines('\n'.join(all_lines))
        
    def compile_harness(self,  harness_code: str, harness_path: Path, fuzzer_name: str, cmd: Optional[str]=None) -> tuple[CompileResults, str]:
        '''Compile the generated harness code (timed: image build vs build_fuzzers, see record_build_timing)'''
        self._image_s: Optional[float] = None
        t0 = time.monotonic()
        res, msg = self._compile_harness(harness_code, harness_path, fuzzer_name, cmd)
        record_build_timing(self.new_project_name, self.sanitizer, self._image_s, time.monotonic() - t0, res)
        return res, msg

    def _compile_harness(self,  harness_code: str, harness_path: Path, fuzzer_name: str, cmd: Optional[str]=None) -> tuple[CompileResults, str]:

        # Run build.sh. There are two possible outcomes:
        # 1. The code compiles successfully.
        # 3. The code compiles but has a compile error. The code should be fixed.

        # write the dockerfile
        self.write_dockerfile(harness_code, harness_path, cmd)
        self.write_build_script()

        # build the image
        t_image = time.monotonic()
        build_flag = False
        for _ in range(3):  # try multiple times to avoid some issues
            if self.docker_tool.build_image(self.build_image_cmd):
                build_flag = True
                break
            time.sleep(5)
        self._image_s = time.monotonic() - t_image
        if not build_flag:
            return CompileResults.ImageError, "Failed to build image"
        
        # recover the dockerfile, so that the harness file is not overwritten

        # run the build command
        process = None
        try:
            # self.docker_tool.run_cmd(["find", "-name", "comp"])
            process = sp.run(self.build_harness_cmd,
                   stdout=sp.PIPE,  # Capture standard output
                    # Important!, build fuzzer error may not appear in stderr, so redirect stderr to stdout
                   stderr=sp.STDOUT,  # Redirect standard error to standard output
                   text=True,  # Get output as text (str) instead of bytes
                   check=True,
                   start_new_session=True
                   ) # Raise exception if build fails

            build_msg = remove_color_characters(process.stdout)
            # succeed to run build command
            fuzzer_name = os.path.join(self.oss_tool.get_path("fuzzer"), fuzzer_name)
            if os.path.exists(fuzzer_name):
                return CompileResults.Success, build_msg
            
            # For net-snmp, compile failed will also not generate the fuzzer but no error is raised
            # TODO: more robust method to check compile error
            else:
                return CompileResults.CodeError, build_msg

        except sp.CalledProcessError as e:
            kill_process(process)
            # remove color characters
            build_msg = remove_color_characters(e.output)
            return CompileResults.CodeError, build_msg

          