# python extract_code.py
import os
import argparse
from pathspec import PathSpec
from pathspec.patterns import GitWildMatchPattern # For .gitignore style

# --- Constants ---
DEFAULT_SKIP_DIRS = {'.git', '.hg', '.svn', 'venv', '.venv', '__pycache__', 'node_modules', 'build', 'dist', 'target' , 'package-lock.json' , 'yarn.lock'}
DEFAULT_BINARY_EXTENSIONS = {
    '.pyc', '.pyo', '.so', '.dll', '.exe', '.bin',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz',
    '.db', '.sqlite', '.sqlite3',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.o', '.a', '.lib', '.class', '.jar',
    '.mp3', '.wav', '.ogg', '.mp4', '.mov', '.avi', '.mkv',
    '.swp', '.swo',
    '.DS_Store'
}
DEFAULT_MAX_FILE_SIZE_MB = 1
DEFAULT_MAX_FILE_SIZE = DEFAULT_MAX_FILE_SIZE_MB * 1024 * 1024

# --- Helper Functions ---

def load_gitignore_patterns(project_dir):
    """بارگذاری الگوها از فایل‌های .gitignore."""
    patterns = []
    gitignore_paths_found = []
    for root, _, files in os.walk(project_dir):
        if '.gitignore' in files:
            gitignore_path = os.path.join(root, '.gitignore')
            gitignore_paths_found.append(os.path.relpath(gitignore_path, project_dir))
            # الگوها باید نسبت به ریشه project_dir باشند برای pathspec
            gitignore_rel_dir = os.path.relpath(root, project_dir)
            if gitignore_rel_dir == '.': gitignore_rel_dir = ''

            with open(gitignore_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # pathspec مسیرها را نسبت به ریشه‌ای که PathSpec از آن ساخته شده، مدیریت می‌کند.
                        # اگر الگو با '/' شروع شود، از ریشه است.
                        # در غیر این صورت، نسبت به فایل .gitignore است.
                        # ما همه چیز را نسبت به project_dir نرمالایز می‌کنیم.
                        if line.startswith('/'):
                            patterns.append(line[1:]) # حذف / ابتدایی چون مسیرهای ما هم از ریشه هستند
                        elif gitignore_rel_dir:
                            patterns.append(os.path.join(gitignore_rel_dir, line).replace(os.sep, '/'))
                        else:
                            patterns.append(line)
    
    if patterns:
        # print(f"Found .gitignore files at: {', '.join(gitignore_paths_found)}")
        # print(f"Effective .gitignore patterns for PathSpec (relative to project root): {patterns[:5]}...") # نمایش تعدادی از الگوها
        return PathSpec.from_lines(GitWildMatchPattern, patterns)
    return None

def should_skip_path(path_rel_to_project, is_dir, project_dir, output_file_abs_path, gitignore_spec, max_size, skip_dirs_set, binary_extensions_set):
    """تشخیص اینکه آیا یک مسیر (فایل یا پوشه) باید رد شود."""
    
    # 1. رد کردن خود فایل خروجی (فقط برای فایل‌ها)
    if not is_dir:
        full_path = os.path.join(project_dir, path_rel_to_project)
        if os.path.abspath(full_path) == output_file_abs_path:
            return True

    # 2. رد کردن پوشه‌های مشخص شده یا پوشه‌های مخفی
    # path_rel_to_project باید با جداکننده / باشد
    parts = path_rel_to_project.split('/')
    if any(part in skip_dirs_set or (part.startswith('.') and part != '.') for part in parts):
        return True

    # 3. رد کردن بر اساس الگوهای .gitignore
    # pathspec انتظار مسیرهای نسبی با جداکننده‌های / را دارد.
    # برای پوشه‌ها، .gitignore ممکن است الگویی مانند `logs/` داشته باشد.
    path_for_gitignore_check = path_rel_to_project
    if is_dir and not path_for_gitignore_check.endswith('/'):
        path_for_gitignore_check += '/'
    
    if gitignore_spec and gitignore_spec.match_file(path_for_gitignore_check):
        # print(f"Skipping (gitignore): {path_for_gitignore_check}")
        return True
    
    # موارد زیر فقط برای فایل‌ها اعمال می‌شوند
    if is_dir:
        return False # اگر پوشه تا اینجا رد نشده، آن را نگه می‌داریم

    # 4. رد کردن فایل‌های باینری بر اساس پسوند
    _, ext = os.path.splitext(path_rel_to_project)
    if ext.lower() in binary_extensions_set:
        return True

    # 5. رد کردن فایل‌های خیلی بزرگ
    try:
        full_path = os.path.join(project_dir, path_rel_to_project)
        if os.path.getsize(full_path) > max_size:
            return True
    except OSError: # فایل وجود ندارد، مجوز و غیره
        return True
        
    return False

def generate_directory_tree(project_dir, output_file_abs_path, gitignore_spec, max_size, skip_dirs, binary_extensions):
    """تولید رشته ساختار درختی برای فایل‌ها و پوشه‌های واجد شرایط."""
    tree_lines = [os.path.basename(project_dir) + "/"] # نام ریشه پروژه

    # باید یک پیمایش انجام دهیم تا آیتم‌های واجد شرایط را پیدا کنیم
    # و سپس ساختار درختی را بر اساس آنها بسازیم.

    # ساختار کمکی برای نگهداری فایل‌ها و پوشه‌های واجد شرایط
    # { 'rel_dir_path': {'dirs': set(), 'files': set()} }
    project_structure = {}

    for root, dirs, files in os.walk(project_dir, topdown=True):
        rel_root = os.path.relpath(root, project_dir).replace(os.sep, '/')
        if rel_root == '.': rel_root = "" # ریشه

        # هرس اولیه پوشه‌ها
        original_dirs = list(dirs) # کپی برای جلوگیری از تغییر در حین پیمایش
        dirs[:] = [
            d for d in original_dirs 
            if not should_skip_path(
                (os.path.join(rel_root, d) if rel_root else d).replace(os.sep, '/'), 
                True, project_dir, output_file_abs_path, gitignore_spec, 
                max_size, skip_dirs, binary_extensions
            )
        ]

        if rel_root not in project_structure:
            project_structure[rel_root] = {'dirs': set(), 'files': set()}

        # اضافه کردن پوشه‌های واجد شرایط به ساختار
        for d_name in sorted(dirs): # مرتب‌سازی برای نمایش ثابت
            project_structure[rel_root]['dirs'].add(d_name)

        # اضافه کردن فایل‌های واجد شرایط به ساختار
        for f_name in sorted(files): # مرتب‌سازی برای نمایش ثابت
            file_rel_path = (os.path.join(rel_root, f_name) if rel_root else f_name).replace(os.sep, '/')
            if not should_skip_path(file_rel_path, False, project_dir, output_file_abs_path, gitignore_spec, max_size, skip_dirs, binary_extensions):
                project_structure[rel_root]['files'].add(f_name)
    
    # تابع بازگشتی برای ساخت رشته درختی
    def build_tree_recursive(current_rel_path, prefix=""):
        # ابتدا اطمینان حاصل کنید که current_rel_path در project_structure وجود دارد
        # این ممکن است برای پوشه‌هایی که خودشان skip شده‌اند اما در یک پیمایش عمیق‌تر به آنها می‌رسیم، ضروری باشد
        # (اگرچه هرس بالا باید از این جلوگیری کند)
        if current_rel_path not in project_structure:
            return

        items_in_current_level = sorted(list(project_structure[current_rel_path]['dirs'])) + \
                                 sorted(list(project_structure[current_rel_path]['files']))
        
        num_items = len(items_in_current_level)

        for i, item_name in enumerate(items_in_current_level):
            is_last = (i == num_items - 1)
            connector = "└── " if is_last else "├── "
            
            is_dir_item = item_name in project_structure[current_rel_path]['dirs']
            
            # اگر پوشه است، '/' را اضافه می‌کنیم
            display_name = item_name + "/" if is_dir_item else item_name
            tree_lines.append(prefix + connector + display_name)
            
            if is_dir_item:
                new_prefix = prefix + ("    " if is_last else "│   ")
                # مسیر نسبی کامل برای زیرپوشه
                subdir_rel_path = os.path.join(current_rel_path, item_name).replace(os.sep, '/') if current_rel_path else item_name
                build_tree_recursive(subdir_rel_path, new_prefix)

    build_tree_recursive("") # شروع از ریشه (مسیر نسبی خالی)
    return "\n".join(tree_lines)


def extract_project_files_to_stream(outfile, project_dir, output_file_abs_path, gitignore_spec, max_size, skip_dirs, binary_extensions):
    """استخراج محتوا به یک stream فایل باز."""
    files_processed_count = 0
    files_skipped_count = 0

    for root, dirs, files in os.walk(project_dir, topdown=True):
        rel_root = os.path.relpath(root, project_dir).replace(os.sep, '/')
        if rel_root == '.': rel_root = ""

        dirs[:] = [
            d for d in dirs 
            if not should_skip_path(
                (os.path.join(rel_root, d) if rel_root else d).replace(os.sep, '/'),
                True, project_dir, output_file_abs_path, gitignore_spec, 
                max_size, skip_dirs, binary_extensions
            )
        ]
        
        for file_name in sorted(files): # مرتب‌سازی برای ترتیب قابل پیش‌بینی
            file_rel_path = (os.path.join(rel_root, file_name) if rel_root else file_name).replace(os.sep, '/')
            
            if should_skip_path(file_rel_path, False, project_dir, output_file_abs_path, gitignore_spec, max_size, skip_dirs, binary_extensions):
                files_skipped_count += 1
                continue
            
            full_file_path = os.path.join(project_dir, file_rel_path)
            
            try:
                content = None
                encodings_to_try = ['utf-8', 'latin-1']
                for enc in encodings_to_try:
                    try:
                        with open(full_file_path, 'r', encoding=enc) as f:
                            content = f.read()
                        if enc != 'utf-8':
                            print(f"توجه: فایل {file_rel_path} با انکودینگ {enc} خوانده شد.")
                        break 
                    except UnicodeDecodeError:
                        if enc == encodings_to_try[-1]: # آخرین تلاش بود
                            raise # دوباره خطا را ایجاد کن تا در except بیرونی گرفته شود
                    except Exception as e_read: # خطاهای دیگر خواندن
                        raise e_read
                
                if content is not None:
                    outfile.write(f"\n\n{'=' * 80}\n")
                    outfile.write(f"FILE: {file_rel_path}\n")
                    outfile.write(f"{'=' * 80}\n\n")
                    outfile.write(content)
                    outfile.write("\n")
                    files_processed_count +=1
                
            except Exception as e:
                outfile.write(f"\n\n{'=' * 80}\n")
                outfile.write(f"FILE: {file_rel_path}\n")
                outfile.write(f"{'=' * 80}\n\n")
                outfile.write(f"[خطا در پردازش فایل: {str(e)}]\n")
                files_skipped_count += 1

    print(f"Processed {files_processed_count} files for content extraction.")
    print(f"Skipped {files_skipped_count} files (binary, large, gitignored, unreadable, etc.) for content extraction.")


def main():
    parser = argparse.ArgumentParser(description="استخراج محتوای فایل‌های متنی و ساختار پوشه از یک دایرکتوری پروژه.")
    parser.add_argument(
        "project_dir", nargs="?", default=os.getcwd(),
        help="دایرکتوری پروژه برای اسکن (پیش‌فرض: دایرکتوری فعلی)."
    )
    parser.add_argument(
        "-o", "--output", default="project_code_export.txt",
        help="فایل خروجی (پیش‌فرض: project_code_export.txt)."
    )
    parser.add_argument(
        "--max-size-mb", type=float, default=DEFAULT_MAX_FILE_SIZE_MB,
        help=f"حداکثر اندازه فایل برای شامل شدن (به مگابایت) (پیش‌فرض: {DEFAULT_MAX_FILE_SIZE_MB}MB)."
    )
    parser.add_argument(
        "--no-gitignore", action="store_true",
        help="نادیده گرفتن فایل‌های .gitignore."
    )

    args = parser.parse_args()

    project_dir_abs = os.path.abspath(args.project_dir)
    output_file_abs = os.path.abspath(args.output)
    
    if not os.path.isdir(project_dir_abs):
        print(f"Error: Project directory '{project_dir_abs}' not found.")
        return

    max_file_size_bytes = int(args.max_size_mb * 1024 * 1024)

    gitignore_spec = None
    if not args.no_gitignore:
        try:
            gitignore_spec = load_gitignore_patterns(project_dir_abs)
            if gitignore_spec:
                 print(f"Loaded .gitignore patterns from '{project_dir_abs}'.")
            else:
                print(f"No .gitignore files found or they are empty in '{project_dir_abs}'.")
        except Exception as e:
            print(f"Warning: Could not load .gitignore patterns: {e}")
    else:
        print("Skipping .gitignore processing as per --no-gitignore flag.")

    print(f"Generating directory tree for {project_dir_abs}...")
    try:
        dir_tree_str = generate_directory_tree(
            project_dir_abs, 
            output_file_abs, # برای اینکه خودش را در درخت نیاورد
            gitignore_spec, 
            max_file_size_bytes,
            DEFAULT_SKIP_DIRS,
            DEFAULT_BINARY_EXTENSIONS
        )
        print("Directory tree generated.")
    except Exception as e_tree:
        print(f"Error generating directory tree: {e_tree}")
        dir_tree_str = "[خطا در تولید ساختار درختی]"


    print(f"Extracting code from {project_dir_abs} to {output_file_abs}...")
    print(f"Max file size: {args.max_size_mb}MB. Binary extensions: {len(DEFAULT_BINARY_EXTENSIONS)} types. Skip dirs: {len(DEFAULT_SKIP_DIRS)} types.")

    with open(output_file_abs, 'w', encoding='utf-8') as outfile:
        outfile.write("ساختار پروژه:\n")
        outfile.write("=" * 20 + "\n")
        outfile.write(dir_tree_str)
        outfile.write("\n\n" + "=" * 80 + "\n")
        outfile.write("محتوای فایل‌ها:\n")
        outfile.write("=" * 20 + "\n")
        
        extract_project_files_to_stream(
            outfile,
            project_dir_abs, 
            output_file_abs, 
            gitignore_spec, 
            max_file_size_bytes,
            DEFAULT_SKIP_DIRS,
            DEFAULT_BINARY_EXTENSIONS
        )
    print(f"انجام شد! خروجی در {output_file_abs} ذخیره شده است")

if __name__ == "__main__":
    main()