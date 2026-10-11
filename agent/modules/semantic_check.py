# this code is copyed from LLM4DG 
import os

class BaseChecker:
    ty = 'BASECHECKER'
    category = None

    funcsig = None

    def do_check(self, arg):
        raise Exception('Not implemented')

class FPChecker(BaseChecker):
    ty = 'FPCHECKER'
    category = 'FP'

class SemanticTester(FPChecker):
    ty = 'SEMATESTER'

    funcsig = None
    check_func = None
    check_func_decl = None
    testcases = None
    main_func = ''' '''

    def hook_api_func(self, code):
        # replace the api func
        return code.replace('%s(' % (self.funcsig), 'check_%s(' % (self.funcsig))

    def add_func_decl(self, code):
        # add the api decl
        if "extern int LLVMFuzzerTestOneInput" in code:
            return code.replace('extern int LLVMFuzzerTestOneInput', self.check_func_decl + '\nextern int LLVMFuzzerTestOneInput')
        else:
            return code.replace('int LLVMFuzzerTestOneInput', self.check_func_decl + '\nint LLVMFuzzerTestOneInput')

    def gen_test_code(self, code):
        test_code = '''
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
''' + code
        test_code = self.hook_api_func(test_code)
        test_code = self.add_func_decl(test_code)

        return '\n'.join([ test_code, self.check_func, self.main_func ])

    def do_check(self, dotestfunc):
        raise Exception('Not implemented')

class igraph_edge_connectivity_Checker(SemanticTester):

    funcsig = 'igraph_edge_connectivity'
    check_func = '''
    igraph_error_t check_igraph_edge_connectivity(const igraph_t * arg1,igraph_integer_t * arg2,igraph_bool_t arg3) {
        igraph_vector_int_t edges;
        long int no_of_edges = igraph_ecount(arg1);

        IGRAPH_VECTOR_INT_INIT_FINALLY(&edges, 0);
        igraph_get_edgelist(arg1, &edges, 0);

        printf("SEMA-CHECK-CONTENT:");
        for (size_t i = 0; i < no_of_edges; ++i) {
            printf("%c", (int) VECTOR(edges)[i]);
        }
        printf("\\n");

        exit(0);

        return IGRAPH_SUCCESS;
    }
    '''
    check_func_decl = 'extern igraph_error_t check_igraph_edge_connectivity(const igraph_t * arg1,igraph_integer_t * arg2,igraph_bool_t arg3);'
    testcases = [ 'A' * 8, 'A' * 8 + '\0', 'A' * 16, 'A' * 16 + '\0', 'A' * 64, 'A' * 64 + '\0' ]
    main_func = SemanticTester.main_func

    def gen_test_code(self, code):
        return '''#include "/src/igraph/include/igraph_conversion.h" \n''' +  super().gen_test_code(code)
     
    def do_check(self, dotestfunc):
        results = {}
        for testcase in self.testcases:
            result = dotestfunc(testcase)
            results[testcase] = result
            if 'SEMA-CHECK-CONTENT:A' in result:
                # any one case works is ok
                return True, result
        
        return False, '\n'.join([ 'Log of case %s:\n%s\n' % (case, log) for case, log in results.items() ])

class stun_is_response_Checker(SemanticTester):
    funcsig = 'stun_is_response'
    check_func = '''
bool check_stun_is_response(const stun_buffer * arg1) {
    printf("SEMA-CHECK-CONTENT:");
    for (size_t i = 0; i < arg1->len; ++i) {
        printf("%c", (uint8_t)arg1->buf[i]);
    }
    printf("\\n");

    exit(0);

    return 0;
}
'''
    check_func_decl = 'extern bool check_stun_is_response(const stun_buffer * arg1);'
    testcases = [ 'A' * 8, 'A' * 8 + '\0', 'A' * 16, 'A' * 16 + '\0', 'A' * 64, 'A' * 64 + '\0' ]
    main_func = SemanticTester.main_func

    def do_check(self, dotestfunc):
        results = {}
        for testcase in self.testcases:
            result = dotestfunc(testcase)
            results[testcase] = result
            if 'SEMA-CHECK-CONTENT:AAAA' in result:
                # any one case works is ok
                return True, result

        return False, '\n'.join([ 'Log of case %s:\n%s\n' % (case, log) for case, log in results.items() ])

class gdk_pixbuf_animation_new_from_file_Checker(SemanticTester):
    funcsig = 'gdk_pixbuf_animation_new_from_file'
    check_func = '''
GdkPixbufAnimation * check_gdk_pixbuf_animation_new_from_file(const char * arg1,GError ** arg2) {
    // 1. file need exist
    // 2. file content not match

    FILE * fPtr = NULL;
    char ch = 0;
    fPtr = fopen(arg1, "r");
    if (fPtr == NULL) {
        // not exist
        printf("Open %s meets error: errno = %d: %s\\n", arg1, errno, strerror(errno));
        exit(0);
    }

    printf("SEMA-CHECK-CONTENT:");
    do {
        ch = fgetc(fPtr);
        printf("%c", ch);
    } while (ch != EOF);
    printf("\\n");

    fclose(fPtr);
    exit(0);

    return 0;
}
'''
    check_func_decl = "extern GdkPixbufAnimation * check_gdk_pixbuf_animation_new_from_file(const char * arg1,GError ** arg2);"
    testcases = [ 'A' * 8, 'A' * 8 + '\0', 'A' * 16, 'A' * 16 + '\0', 'A' * 64, 'A' * 64 + '\0' ]
    main_func = SemanticTester.main_func

    def do_check(self, dotestfunc):
        results = {}
        for testcase in self.testcases:
            result = dotestfunc(testcase)
            results[testcase] = result
            if 'SEMA-CHECK-CONTENT:AAAA' in result:
                # any one case works is ok
                return True, result
            
        return False, '\n'.join([ 'Log of case %s:\n%s\n' % (case, log) for case, log in results.items() ])

class gdk_pixbuf_new_from_file_Checker(SemanticTester):
    funcsig = 'gdk_pixbuf_new_from_file'
    check_func = '''
GdkPixbuf * check_gdk_pixbuf_new_from_file(const char * arg1,GError ** arg2) {
    // 1. file need exist
    // 2. file content not match

    FILE * fPtr = NULL;
    char ch = 0;
    fPtr = fopen(arg1, "r");
    if (fPtr == NULL) {
        // not exist
        printf("Open %s meets error: errno = %d: %s\\n", arg1, errno, strerror(errno));
        exit(0);
    }

    printf("SEMA-CHECK-CONTENT:");
    do {
        ch = fgetc(fPtr);
        printf("%c", ch);
    } while (ch != EOF);
    printf("\\n");

    fclose(fPtr);
    exit(0);

    return 0;
}
'''
    check_func_decl = "extern GdkPixbuf * check_gdk_pixbuf_new_from_file(const char * arg1,GError ** arg2);"
    testcases = [ 'A' * 8, 'A' * 8 + '\0', 'A' * 16, 'A' * 16 + '\0', 'A' * 64, 'A' * 64 + '\0' ]
    main_func = SemanticTester.main_func

    def do_check(self, dotestfunc):
        results = {}
        for testcase in self.testcases:
            result = dotestfunc(testcase)
            results[testcase] = result
            if 'SEMA-CHECK-CONTENT:AAAA' in result:
                # any one case works is ok
                return True, result

        return False, '\n'.join([ 'Log of case %s:\n%s\n' % (case, log) for case, log in results.items() ])

class gdk_pixbuf_new_from_file_at_scale_Checker(SemanticTester):
    funcsig = 'gdk_pixbuf_new_from_file_at_scale'
    check_func = '''
GdkPixbuf * check_gdk_pixbuf_new_from_file_at_scale(const char * arg1,int arg2,int arg3,gboolean arg4,GError ** arg5) {
    // 1. file need exist
    // 2. file content not match

    FILE * fPtr = NULL;
    char ch = 0;
    fPtr = fopen(arg1, "r");
    if (fPtr == NULL) {
        // not exist
        printf("Open %s meets error: errno = %d: %s\\n", arg1, errno, strerror(errno));
        exit(0);
    }

    printf("SEMA-CHECK-CONTENT:");
    do {
        ch = fgetc(fPtr);
        printf("%c", ch);
    } while (ch != EOF);
    printf("\\n");

    fclose(fPtr);
    exit(0);

    return 0;
}
'''
    check_func_decl = "extern GdkPixbuf * check_gdk_pixbuf_new_from_file_at_scale(const char * arg1,int arg2,int arg3,gboolean arg4,GError ** arg5);"
    testcases = [ 'A' * 8, 'A' * 8 + '\0', 'A' * 16, 'A' * 16 + '\0', 'A' * 64, 'A' * 64 + '\0' ]
    main_func = SemanticTester.main_func

    def do_check(self, dotestfunc):
        results = {}
        for testcase in self.testcases:
            result = dotestfunc(testcase)
            results[testcase] = result
            if 'SEMA-CHECK-CONTENT:AAAA' in result:
                # any one case works is ok
                return True, result

        return False, '\n'.join([ 'Log of case %s:\n%s\n' % (case, log) for case, log in results.items() ])

class gf_isom_open_file_Checker(SemanticTester):
    funcsig = 'gf_isom_open_file'
    check_func = '''
GF_ISOFile * check_gf_isom_open_file(const char * arg1,GF_ISOOpenMode arg2,const char * arg3) {
    // 1. file need exist
    // 2. file content not match

    FILE * fPtr = NULL;
    char ch = 0;
    fPtr = fopen(arg1, "r");
    if (fPtr == NULL) {
        // not exist
        printf("Open %s meets error: errno = %d: %s\\n", arg1, errno, strerror(errno));
        exit(0);
    }

    printf("SEMA-CHECK-CONTENT:");
    do {
        ch = fgetc(fPtr);
        printf("%c", ch);
    } while (ch != EOF);
    printf("\\n");

    fclose(fPtr);
    exit(0);

    return 0;
}
'''
    check_func_decl = "extern GF_ISOFile * check_gf_isom_open_file(const char * arg1,GF_ISOOpenMode arg2,const char * arg3);"
    testcases = [ 'A' * 8, 'A' * 8 + '\0', 'A' * 16, 'A' * 16 + '\0', 'A' * 64, 'A' * 64 + '\0' ]
    main_func = SemanticTester.main_func

    def do_check(self, dotestfunc):
        results = {}
        for testcase in self.testcases:
            result = dotestfunc(testcase)
            results[testcase] = result
            if 'SEMA-CHECK-CONTENT:AAAA' in result:
                # any one case works is ok
                return True, result

        return False, '\n'.join([ 'Log of case %s:\n%s\n' % (case, log) for case, log in results.items() ])

class dwarf_init_path_Checker(SemanticTester):
    funcsig = 'dwarf_init_path'
    check_func = '''
int check_dwarf_init_path(const char * arg1,char * arg2,unsigned int arg3,unsigned int arg4,Dwarf_Handler arg5,Dwarf_Ptr arg6,Dwarf_Debug * arg7,Dwarf_Error * arg8) {
    // 1. file need exist
    // 2. file content not match

    FILE * fPtr = NULL;
    char ch = 0;
    fPtr = fopen(arg1, "r");
    if (fPtr == NULL) {
        // not exist
        printf("Open %s meets error: errno = %d: %s\\n", arg1, errno, strerror(errno));
        exit(0);
    }

    printf("SEMA-CHECK-CONTENT:");
    do {
        ch = fgetc(fPtr);
        printf("%c", ch);
    } while (ch != EOF);
    printf("\\n");

    fclose(fPtr);
    exit(0);

    return 0;
}
'''
    check_func_decl = "extern int check_dwarf_init_path(const char * arg1,char * arg2,unsigned int arg3,unsigned int arg4,Dwarf_Handler arg5,Dwarf_Ptr arg6,Dwarf_Debug * arg7,Dwarf_Error * arg8);"
    testcases = [ 'A' * 8, 'A' * 8 + '\0', 'A' * 16, 'A' * 16 + '\0', 'A' * 64, 'A' * 64 + '\0' ]
    main_func = SemanticTester.main_func

    def do_check(self, dotestfunc):
        results = {}
        for testcase in self.testcases:
            result = dotestfunc(testcase)
            results[testcase] = result
            if 'SEMA-CHECK-CONTENT:AAAA' in result:
                # any one case works is ok
                return True, result

        return False, '\n'.join([ 'Log of case %s:\n%s\n' % (case, log) for case, log in results.items() ])

class ixmlLoadDocumentEx_Checker(SemanticTester):
    funcsig = 'ixmlLoadDocumentEx'
    check_func = '''
int check_ixmlLoadDocumentEx(const char * arg1,IXML_Document ** arg2) {
    // 1. file need exist
    // 2. file content not match

    FILE * fPtr = NULL;
    char ch = 0;
    fPtr = fopen(arg1, "r");
    if (fPtr == NULL) {
        // not exist
        printf("Open %s meets error: errno = %d: %s\\n", arg1, errno, strerror(errno));
        exit(0);
    }

    printf("SEMA-CHECK-CONTENT:");
    do {
        ch = fgetc(fPtr);
        printf("%c", ch);
    } while (ch != EOF);
    printf("\\n");

    fclose(fPtr);
    exit(0);

    return 0;
}
'''
    check_func_decl = "extern int check_ixmlLoadDocumentEx(const char * arg1,IXML_Document ** arg2);"
    testcases = [ 'A' * 8, 'A' * 8 + '\0', 'A' * 16, 'A' * 16 + '\0', 'A' * 64, 'A' * 64 + '\0' ]
    main_func = SemanticTester.main_func

    def do_check(self, dotestfunc):
        results = {}
        for testcase in self.testcases:
            result = dotestfunc(testcase)
            results[testcase] = result
            if 'SEMA-CHECK-CONTENT:AAAA' in result:
                # any one case works is ok
                return True, result

        return False, '\n'.join([ 'Log of case %s:\n%s\n' % (case, log) for case, log in results.items() ])



checker_list = {
    # SemanticTester 8
    "igraph_edge_connectivity": igraph_edge_connectivity_Checker, # P
    "stun_is_response": stun_is_response_Checker,
    "gdk_pixbuf_animation_new_from_file": gdk_pixbuf_animation_new_from_file_Checker,  # P
    "gdk_pixbuf_new_from_file": gdk_pixbuf_new_from_file_Checker, # P
    "gdk_pixbuf_new_from_file_at_scale": gdk_pixbuf_new_from_file_at_scale_Checker,  # P
    "gf_isom_open_file": gf_isom_open_file_Checker,
    "dwarf_init_path": dwarf_init_path_Checker,
    "ixmlLoadDocumentEx": ixmlLoadDocumentEx_Checker,  # P
}

kamailio_func = [
	# CodeChecker 15
	"get_src_address_socket",
	"get_src_uri",
	"parse_content_disposition",
	"parse_diversion_header",
	"parse_from_header",
	"parse_from_uri",
	"parse_headers",
	"parse_identityinfo_header",
	"parse_pai_header",
	"parse_privacy",
	"parse_record_route_headers",
	"parse_refer_to_header",
	"parse_route_headers",
	"parse_to_header",
	"parse_to_uri",
]

class CodeChecker():

	def do_check(self, code):
		for line in code.split('\n'):
			if not line.strip().startswith('//'):
				if not line.strip().startswith('extern'):
					if 'parse_msg(' in code:
						return True
		return False

from agent_tools.fuzz_tools.compiler import Compiler
from utils.oss_fuzz_utils import OSSFuzzUtils
import shutil
from agent_tools.fuzz_tools.compiler import Compiler
from pathlib import Path
from constants import CompileResults, LanguageType
import random
from utils.oss_fuzz_utils import OSSFuzzUtils
from utils.docker_utils import DockerUtils
import re

class SemaCheck():
    def __init__(self, oss_fuzz_dir: Path, benchmark_dir: Path, project_name: str, new_project_name: str, func_name: str, project_lang: LanguageType):
        self.oss_fuzz_dir = oss_fuzz_dir
        self.benchmark_dir = benchmark_dir
        self.project_name = project_name
        self.new_project_name = new_project_name
        self.func_name = func_name
        self.docker_tool = DockerUtils(oss_fuzz_dir, project_name, new_project_name, project_lang)
        
    def check(self, harness_code: str,  fuzzer_path: Path, fuzzer_name: str) -> bool:

        # remove all comments
        harness_code = '\n'.join([line for line in harness_code.split('\n') if not line.strip().startswith('//')])
        # comments between /* and */
        harness_code = re.sub(r'/\*.*?\*/', '', harness_code, flags=re.DOTALL)

        if self.func_name in checker_list.keys():

            def dotestfunc(testcase: str):

                # sh -c for shell command
                cmd = ["sh", "-c", f"echo -n {testcase} > testcase && ./{fuzzer_name} testcase -runs=1"]

                compile_out_path = os.path.join(self.oss_fuzz_dir, "build", "out", self.new_project_name)
                volumes={compile_out_path: {"bind": "/out", "mode": "rw"}}
                outputs = self.docker_tool.run_cmd(cmd, working_dir="/out/", volumes=volumes)
                return outputs
            
            checker = checker_list[self.func_name]()
            wrapped_code = checker.gen_test_code(harness_code)

            # init the compiler
            compiler = Compiler(self.oss_fuzz_dir,self.benchmark_dir, self.project_name, self.new_project_name)
            # compile the code
            compile_res, build_msg = compiler.compile_harness(wrapped_code, fuzzer_path, fuzzer_name)
            if compile_res != CompileResults.Success:
                # print(f"Compile error: {build_msg}")
                return False
        
            # run fuzzer driver with testcase
            res, _ = checker.do_check(dotestfunc)
            return res
        
        elif self.func_name in kamailio_func:
            return CodeChecker().do_check(harness_code)
        else:
            # No need to check
            return True
        
    def clean_workspace(self):
        '''Clean the workspace'''
        try:        
            # first remove the out directory
            self.docker_tool.clean_build_dir()
            # remove the docker image here
            self.docker_tool.remove_image()
            # remove the project directory
            shutil.rmtree(os.path.join(self.oss_fuzz_dir, "projects", self.new_project_name))
            # clean the build directory
            shutil.rmtree(os.path.join(self.oss_fuzz_dir, "build", "out", self.new_project_name))

        except:
            pass

if __name__ == '__main__':
    from pathlib import Path

    benchmark_root = Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/benchmark-sets/function_0/")
    oss_fuzz_dir = Path("/home/ubuntu/fuzzing_workspace/oss-fuzz/")
    project_name = "gdk-pixbuf"
    random_str = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=16))
    new_project_name = "{}_{}".format(project_name, random_str)
    
    scr_path = oss_fuzz_dir / "projects" / project_name
    dst_path = oss_fuzz_dir / "projects" / new_project_name

    oss_tool = OSSFuzzUtils(oss_fuzz_dir, benchmark_root, project_name, new_project_name)
    project_fuzzer_name, project_harness_path  = oss_tool.get_harness_and_fuzzer()
    project_lang = oss_tool.get_project_language()

    shutil.copytree(scr_path, dst_path, dirs_exist_ok=True)

    function_name = "gdk_pixbuf_new_from_file"
    # test the semantic check
    harness_path = Path("/home/ubuntu/fuzzing_workspace/LLM-reasoning-agents/outputs_ablation/gpt5-mini/code_info/agent/gdk-pixbuf/gdk_pixbuf_new_from_file/run1_cxfbgmttnyvtdfue/draft_fix0.txt")
    flag = SemaCheck(oss_fuzz_dir, project_name, new_project_name, function_name, project_lang).check(harness_path.read_text(), project_harness_path,  project_fuzzer_name)
    print(f"Semantic check result: {flag}")