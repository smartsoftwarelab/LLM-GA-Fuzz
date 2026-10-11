#!/usr/bin/env python3
"""
Extract specific function definition and declaration using libclang and compile_commands.json
"""

import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Optional, Any
from clang import cindex
from clang.cindex import CursorKind, Index, Cursor


class ClangParser:
    def __init__(self, compile_commands_path: str):
        """
        Initialize the symbol extractor with compile_commands.json
        
        Args:
            compile_commands_path: Path to compile_commands.json file
        """
        self.compile_commands_path = Path(compile_commands_path)
        self.compile_commands = self._load_compile_commands()
        self.index = Index.create()
        
    def _load_compile_commands(self) -> List[Dict[str, str]]:
        """Load and parse compile_commands.json"""
        try:
            with open(self.compile_commands_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"compile_commands.json not found at {self.compile_commands_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in compile_commands.json: {e}")
    
    def _get_compile_args(self, file_path: str) -> Optional[List[str]]:
        """
        Get compilation arguments for a specific file
        
        Args:
            file_path: Path to the source file
            
        Returns:
            List of compilation arguments or None if not found
        """
        abs_file_path = os.path.abspath(file_path)
        
        for entry in self.compile_commands:
            # Handle relative paths in file field
            if os.path.isabs(entry['file']):
                entry_file = os.path.abspath(entry['file'])
            else:
                entry_file = os.path.abspath(os.path.join(entry.get('directory', ''), entry['file']))
            
            if entry_file == abs_file_path:
                # Parse command arguments
                if 'arguments' in entry:
                    args = entry['arguments'][1:]  # Skip compiler name (first argument)
                elif 'command' in entry:
                    # Split command string into arguments
                    import shlex
                    args = shlex.split(entry['command'])[1:]  # Skip compiler name
                else:
                    continue
                
                # Filter out problematic arguments for libclang
                filtered_args:list[str] = []
                skip_next = False
                
                for i, arg in enumerate(args):
                    if skip_next:
                        skip_next = False
                        continue
                        
                    # Skip output file arguments
                    if arg == '-o':
                        skip_next = True  # Skip the next argument (output file)
                        continue
                    if arg.startswith('-o') and len(arg) > 2:
                        continue  # Skip -ofile.o format
                        
                    # Skip compilation-only flag
                    if arg == '-c':
                        continue
                        
                    # Skip source file (last argument typically)
                    if i == len(args) - 1 and (arg.endswith('.cpp') or arg.endswith('.cc') or 
                                               arg.endswith('.c') or arg.endswith('.cxx')):
                        continue
                    
                    # Handle -isystem separately (it takes an argument)
                    if arg == '-isystem':
                        if i + 1 < len(args):
                            filtered_args.extend(['-isystem', args[i + 1]])
                            skip_next = True
                        continue
                    
                    # Keep include paths, defines, standards, and other relevant flags
                    if (arg.startswith('-I') or arg.startswith('-D') or 
                        arg.startswith('-std=') or arg.startswith('-stdlib=') or
                        arg.startswith('-f') and not arg.startswith('-fsanitize') or
                        arg.startswith('-W') or arg.startswith('-g') or
                        arg.startswith('-O') or arg == '-Wall' or arg == '-Wextra' or
                        arg.startswith('-Wno-') or arg.startswith('-march=') or
                        arg.startswith('-mtune=') or arg.startswith('-m64') or
                        arg.startswith('-m32')):
                        filtered_args.append(arg)
                
                return filtered_args
        
        return None
    
    def _extract_symbol_info(self, cursor: Cursor) -> Dict[str, Any]:
        """Extract detailed information about a symbol (function/method)"""
       
        info: dict[str, Any] = {
            'name': cursor.spelling,
            'kind': cursor.kind.name,
            'return_type': None,
            'parameters': [],
            'location': {
                'file': cursor.location.file.name if cursor.location.file else None,
                'line': cursor.location.line,
            },
            'extent': {
                'start_line': cursor.extent.start.line,
                'end_line': cursor.extent.end.line,
            },
            'is_definition': cursor.is_definition(),
            'source_text': None
        }
        
        # Extract return type for functions
        if cursor.kind in [CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD]:
            info['return_type'] = cursor.result_type.spelling
            
            # Extract parameter information
            for param in cursor.get_arguments():
                param_info = {
                    'name': param.spelling,
                    'type': param.type.spelling
                }
                info['parameters'].append(param_info)
            
            # Get function signature
       
            param_strings = [f"{p['type']} {p['name']}" for p in info['parameters']]
            param_strings = ', '.join(param_strings)
            info['signature'] = f"{info['return_type']} {info['name']}({param_strings})"
        
        return info
    
    def _get_source_text(self, file_path: str, start_line: int, end_line: int) -> str:
        """Extract source text between specified lines"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Convert to 0-based indexing and extract lines
                start_idx = max(0, start_line - 1)
                end_idx = min(len(lines), end_line)
                return ''.join(lines[start_idx:end_idx])
        except Exception as e:
            return f"Error reading source: {e}"
    
    def _find_symbol_at_location(self, cursor: Cursor, symbol_name: str, target_line: int, 
                                file_path: str, results: List[Dict[str, Any]]):
        """Find symbol at specific location (line number)"""
        # Check if this cursor is at or near the target line
        if (cursor.location.file and 
            os.path.abspath(cursor.location.file.name) == os.path.abspath(file_path) and
            cursor.spelling == symbol_name):
            
            # Check if cursor is at the target line or within a reasonable range
            if abs(cursor.location.line - target_line) <= 2:  # Allow some tolerance
                symbol_info = self._extract_symbol_info(cursor)
                
                # Get source text for the symbol
                symbol_info['source_text'] = self._get_source_text(
                    file_path, 
                    symbol_info['extent']['start_line'],
                    symbol_info['extent']['end_line']
                )
                
                results.append(symbol_info)
        
        # Recursively search children
        for child in cursor.get_children():
            self._find_symbol_at_location(child, symbol_name, target_line, file_path, results)
    
    def _find_all_symbols_by_name(self, cursor: Cursor, symbol_name: str, results: List[Dict]):
        """Find all occurrences of a symbol by name"""
        if cursor.spelling == symbol_name:
            # Only include function/method declarations and definitions
            if cursor.kind in [CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD, 
                              CursorKind.VAR_DECL, CursorKind.FIELD_DECL]:
                symbol_info = self._extract_symbol_info(cursor)
                
                # Get source text for the symbol
                if symbol_info['location']['file']:
                    symbol_info['source_text'] = self._get_source_text(
                        symbol_info['location']['file'],
                        symbol_info['extent']['start_line'],
                        symbol_info['extent']['end_line']
                    )
                
                results.append(symbol_info)
        
        # Recursively search children
        for child in cursor.get_children():
            self._find_all_symbols_by_name(child, symbol_name, results)
    
    def extract_symbol(self, file_path: str, symbol_name: str, 
                      line_number: Optional[int] = None) -> Dict[str, Any]:
        """
        Extract symbol definition and declaration
        
        Args:
            file_path: Path to the source file
            symbol_name: Name of the symbol to extract
            line_number: Optional line number to narrow down search
            
        Returns:
            Dictionary containing symbol information
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Source file not found: {file_path}")
        
        # Get compilation arguments for this file
        compile_args = self._get_compile_args(file_path)
        if compile_args is None:
            print(f"Warning: No compile commands found for {file_path}, using default args")
            compile_args = ['-std=c++17']  # Default fallback
        
        try:
            # Parse the file
            tu = self.index.parse(file_path, args=compile_args)
            
            # Check for parsing errors
            # if tu.diagnostics:
            #     print(f"Parsing warnings/errors for {file_path}:")
            #     for diag in tu.diagnostics:
            #         if diag.severity >= 3:  # Error or Fatal
            #             print(f"  {diag.severity.name if hasattr(diag.severity, 'name') else diag.severity}: {diag.spelling}")
            
            results = []
            
            if line_number is not None:
                # Search for symbol at specific line
                self._find_symbol_at_location(tu.cursor, symbol_name, line_number, 
                                            file_path, results)
            else:
                # Search for all occurrences of the symbol
                self._find_all_symbols_by_name(tu.cursor, symbol_name, results)
            
            # Separate definitions and declarations
            definitions = [r for r in results if r['is_definition']]
            declarations = [r for r in results if not r['is_definition']]
            
            return {
                'symbol_name': symbol_name,
                'file_path': file_path,
                'line_number': line_number,
                'definitions': definitions,
                'declarations': declarations,
                'total_found': len(results)
            }
            
        except Exception as e:
            raise RuntimeError(f"Failed to parse {file_path}: {e}")
    

def main():
    """Command line interface"""
    if len(sys.argv) < 4:
        print("Usage: python symbol_extractor.py <compile_commands.json> <source_file> <symbol_name> [line_number]")
        print("  compile_commands.json: Path to compile_commands.json")
        print("  source_file: Source file path (as it appears in compile_commands.json)")
        print("  symbol_name: Name of the function/symbol to extract")
        print("  line_number: Optional line number to narrow down search")
        print("\nExample:")
        print("  python symbol_extractor.py compile_commands.json src/main.cpp my_function 42")
        return
    
    compile_commands_path = sys.argv[1]
    source_file = sys.argv[2]
    symbol_name = sys.argv[3]
    line_number = int(sys.argv[4]) if len(sys.argv) >= 5 else None
    
    try:
        extractor = ClangParser(compile_commands_path)
        result = extractor.extract_symbol(source_file, symbol_name, line_number)
        extractor.print_symbol_info(result)
        
        if result['total_found'] == 0:
            print(f"\nNo symbol '{symbol_name}' found in {source_file}")
            if line_number:
                print(f"at or near line {line_number}")
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()