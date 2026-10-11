from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel, Field
import re
import tiktoken


class CodeAnswerStruct(BaseModel):
    """Split the answer into the content before the code, the code, and the content after the code."""
    before_code: str = Field(description="The unnecessary explanation before the code.")
    source_code: str = Field(description="The harness code part of the answer.")
    after_code: str = Field(description="The unnecessary explanation after the code.")


class CodeFormatTool():

    def __init__(self, llm: BaseChatModel, prompt: str):
        self.llm = llm
        self.prompt = prompt

    def extract_code(self, response: str) -> str:
        '''Extract the code from the response with LLM'''

        enc = tiktoken.encoding_for_model("gpt-4o")
        extract_prompt = self.prompt.format(response=response)
        # Trim the response from the top until the prompt fits within the token limit
        if len(enc.encode(extract_prompt)) > 2000:
            lines = response.splitlines()
            while lines and len(enc.encode(self.prompt.format(response="\n".join(lines)))) > 2000:
                lines = lines[1:]
            extract_prompt = self.prompt.format(response="\n".join(lines))

        _respsone: CodeAnswerStruct = self.llm.invoke(extract_prompt) # type: ignore
        source_code = _respsone.source_code 
        # deal with the new line
        # if "\\n" in source_code:
            # source_code = source_code.replace("\\n", "\n")

        
        # remove the line number if exists
        source_code = re.sub(r'^//\s+\d+:\s?', '', source_code, flags=re.MULTILINE)
        # remove ALL code fence markers: ```cpp, ```c++, ```c, ```java, ``` etc.
        source_code = re.sub(r'```[a-zA-Z+]*\n?', '', source_code)
        return source_code.strip() + "\n"
        
        # # remove some useless string
        # source_code = source_code.replace("```cpp", "")
        # source_code = source_code.replace("```", "")
        # # if source_code and source_code.startswith("c\n"):
        #     # source_code = source_code[1:]
        # return source_code