#!/usr/bin/env python3
"""
Script to count symbols for each directory from All_all_symbols_lsp.json
"""

import json
import os
from collections import defaultdict
from pathlib import Path
import argparse


def should_exclude_path(path, exclude_paths):
    """
    Check if a path should be excluded based on the exclude list.
    
    Args:
        path: Directory path to check
        exclude_paths: List of paths to exclude (exact match or starts with)
    
    Returns:
        bool: True if path should be excluded, False otherwise
    """
    if not exclude_paths:
        return False
    
    for exclude in exclude_paths:
        # Check if path exactly matches or starts with the exclude path
        if path == exclude or path.startswith(exclude + '/'):
            return True
    return False


def remove_excluded_from_file(json_file_path, exclude_paths, backup=True):
    """
    Remove excluded symbols from the JSON file and overwrite it.
    
    Args:
        json_file_path: Path to the All_all_symbols_lsp.json file to modify
        exclude_paths: List of directory paths to exclude
        backup: Whether to create a backup of the original file
    
    Returns:
        tuple: (original_count, removed_count, remaining_count)
    """
    # Load the JSON file
    with open(json_file_path, 'r') as f:
        symbols = json.load(f)
    
    original_count = len(symbols)
    
    # Create backup if requested
    if backup:
        backup_path = json_file_path + '.backup'
        with open(backup_path, 'w') as f:
            json.dump(symbols, f, indent=2)
    
    # Filter out excluded symbols
    filtered_symbols = []
    removed_count = 0
    
    for symbol in symbols:
        file_path = symbol.get('file_path', '')
        if file_path:
            directory = os.path.dirname(file_path)
            if should_exclude_path(directory, exclude_paths):
                removed_count += 1
            else:
                filtered_symbols.append(symbol)
        else:
            filtered_symbols.append(symbol)
    
    # Overwrite the original file with filtered symbols
    with open(json_file_path, 'w') as f:
        json.dump(filtered_symbols, f, indent=2)
    
    return original_count, removed_count, len(filtered_symbols)


def count_symbols_by_directory(json_file_path, max_depth=None, exclude_paths=None):
    """
    Count symbols for each directory from the LSP symbols JSON file.
    
    Args:
        json_file_path: Path to the All_all_symbols_lsp.json file
        max_depth: Maximum directory depth to display (None for all levels)
        exclude_paths: List of directory paths to exclude (None for no exclusions)
    
    Returns:
        dict: Dictionary with directory paths as keys and symbol counts as values
    """
    # Load the JSON file
    with open(json_file_path, 'r') as f:
        symbols = json.load(f)
    
    # Count symbols per directory
    dir_counts = defaultdict(int)
    
    for symbol in symbols:
        file_path = symbol.get('file_path', '')
        if file_path:
            # Extract directory from file path
            directory = os.path.dirname(file_path)
            
            # Skip if directory should be excluded
            if should_exclude_path(directory, exclude_paths):
                continue
            
            dir_counts[directory] += 1
            
            # Also count parent directories if max_depth is set
            if max_depth is not None:
                parts = directory.split('/')
                for depth in range(1, min(len(parts), max_depth + 1)):
                    parent_dir = '/'.join(parts[:depth])
                    if parent_dir:
                        dir_counts[parent_dir] += 1
    
    return dir_counts


def print_directory_counts(dir_counts, sort_by='count', top_n=None):
    """
    Print directory symbol counts.
    
    Args:
        dir_counts: Dictionary with directory paths and counts
        sort_by: Sort by 'count' (descending) or 'path' (alphabetical)
        top_n: Only show top N directories (None for all)
    """
    # Sort the results
    if sort_by == 'count':
        sorted_dirs = sorted(dir_counts.items(), key=lambda x: x[1], reverse=True)
    else:
        sorted_dirs = sorted(dir_counts.items(), key=lambda x: x[0])
    
    # Limit to top N if specified
    if top_n is not None:
        sorted_dirs = sorted_dirs[:top_n]
    
    # Print results
    print(f"{'Directory':<80} {'Symbol Count':>12}")
    print("=" * 95)
    
    for directory, count in sorted_dirs:
        print(f"{directory:<80} {count:>12,}")
    
    print("=" * 95)
    print(f"Total directories: {len(dir_counts)}")
    print(f"Total symbols: {sum(dir_counts.values())}")


def count_by_depth_level(json_file_path, depth=1, exclude_paths=None):
    """
    Count symbols by directory at a specific depth level.
    
    Args:
        json_file_path: Path to the All_all_symbols_lsp.json file
        depth: Directory depth level (1 = top level)
        exclude_paths: List of directory paths to exclude (None for no exclusions)
    
    Returns:
        dict: Dictionary with directory paths at specified depth and counts
    """
    with open(json_file_path, 'r') as f:
        symbols = json.load(f)
    
    dir_counts = defaultdict(int)
    
    for symbol in symbols:
        file_path = symbol.get('file_path', '')
        if file_path:
            directory = os.path.dirname(file_path)
            
            # Skip if directory should be excluded
            if should_exclude_path(directory, exclude_paths):
                continue
            
            parts = [p for p in directory.split('/') if p]  # Remove empty strings
            
            if len(parts) >= depth:
                # Get directory at specified depth
                dir_at_depth = '/'.join([''] + parts[:depth])
                dir_counts[dir_at_depth] += 1
    
    return dir_counts


def main():
    parser = argparse.ArgumentParser(
        description='Count symbols per directory from All_all_symbols_lsp.json'
    )
    parser.add_argument(
        'json_file',
        help='Path to All_all_symbols_lsp.json file'
    )
    parser.add_argument(
        '--sort',
        choices=['count', 'path'],
        default='count',
        help='Sort by count (descending) or path (alphabetical)'
    )
    parser.add_argument(
        '--top',
        type=int,
        help='Show only top N directories'
    )
    parser.add_argument(
        '--depth',
        type=int,
        help='Group by directory at specific depth level (1=top level, 2=second level, etc.)'
    )
    parser.add_argument(
        '--output',
        help='Output results to CSV file'
    )
    parser.add_argument(
        '--exclude',
        action='append',
        help='Exclude directories matching this path (can be used multiple times). Example: --exclude /src/openssl/providers --exclude /src/openssl/fuzz'
    )
    parser.add_argument(
        '--remove-excluded',
        action='store_true',
        help='Remove excluded paths from the original JSON file (creates a .backup file first)'
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Do not create a backup when removing excluded paths'
    )
    
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.exists(args.json_file):
        print(f"Error: File not found: {args.json_file}")
        return 1
    
    print(f"Processing: {args.json_file}")
    
    # Show exclusions if any
    if args.exclude:
        print(f"Excluding paths: {', '.join(args.exclude)}")
        
        # Remove excluded symbols from file if requested
        if args.remove_excluded:
            create_backup = not args.no_backup
            original_count, removed_count, remaining_count = remove_excluded_from_file(
                args.json_file, args.exclude, backup=create_backup
            )
            if create_backup:
                print(f"Created backup: {args.json_file}.backup")
            print(f"Removed {removed_count:,} symbols from {args.json_file}")
            print(f"Original: {original_count:,} symbols -> Remaining: {remaining_count:,} symbols")
    print()
    
    # Count symbols
    if args.depth:
        print(f"Counting symbols by directory at depth level {args.depth}")
        print()
        dir_counts = count_by_depth_level(args.json_file, args.depth, exclude_paths=args.exclude)
    else:
        print("Counting symbols by directory (all levels)")
        print()
        dir_counts = count_symbols_by_directory(args.json_file, exclude_paths=args.exclude)
    
    # Print results
    print_directory_counts(dir_counts, sort_by=args.sort, top_n=args.top)
    
    # Save to CSV if requested
    if args.output:
        import csv
        with open(args.output, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Directory', 'Symbol Count'])
            
            if args.sort == 'count':
                sorted_dirs = sorted(dir_counts.items(), key=lambda x: x[1], reverse=True)
            else:
                sorted_dirs = sorted(dir_counts.items(), key=lambda x: x[0])
            
            for directory, count in sorted_dirs:
                writer.writerow([directory, count])
        
        print()
        print(f"Results saved to: {args.output}")
    
    return 0


if __name__ == '__main__':
    exit(main())
