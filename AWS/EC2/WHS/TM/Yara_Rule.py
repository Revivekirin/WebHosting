import yara
import os

def compile_rules(rules_directory):
    try:
        if not os.path.isdir(rules_directory):
            raise ValueError(f"Directory does not exist: {rules_directory}")

        rule_filepaths = {}
        for root, dirs, files in os.walk(rules_directory):
            for filename in files:
                if filename.endswith((".yar", ".yara")):
                    rule_namespace = os.path.splitext(filename)[0]
                    rule_path = os.path.join(root, filename)
                    try:
                        if os.path.exists(rule_path):
                            rule_filepaths[rule_namespace] = rule_path
                    except Exception as e:
                        print(f"An unexpected error occurred while checking {rule_path}: {e}")

        return yara.compile(filepaths=rule_filepaths)
    except yara.YaraSyntaxError as e:
        print(f"Error compiling YARA rules: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def scan_exe_files(rules, target_directory):
    try:
        for root, dirs, files in os.walk(target_directory):
            output_file_path = os.path.join(root, f"yara_scan_results_{os.path.basename(root)}.txt")

            with open(output_file_path, 'w') as output:
                for filename in files:
                    if filename.endswith(".exe"):
                        file_path = os.path.join(root, filename)
                        scan_file(file_path, rules, output)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def scan_file(file_path, rules, output_file):
    try:
        if rules is None:
            raise ValueError("Rules compilation failed.")

        with open(file_path, 'rb') as file:
            data = file.read()
            matches = rules.match(data=data)

            if matches:
                output_file.write(f"YARA rules matched in {file_path}:\n")
                for match in matches:
                    rule_name = match.rule
                    output_file.write(f"Rule: {rule_name}\n")
                    matched_strings = match.strings
                    if matched_strings:
                        output_file.write(f"Matched Strings:\n")
                        for string_match in matched_strings:
                            if isinstance(string_match, yara.StringMatch):
                                output_file.write(f"  - {string_match}\n")
                            else:
                                output_file.write("  - Unexpected data type in StringMatch.\n")
                    else:
                        output_file.write("No matched strings.\n")
            else:
                output_file.write(f"No YARA rules matched in {file_path}\n")
    except ValueError as ve:
        print(ve)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # YARA 룰 디렉토리 
    yara_rules_directory = "/home/ubuntu/WHS/YARA_Rules_Directory"
    # YARA 룰 타겟 디렉토리
    target_directory = "/home/ubuntu/WHS/TM/collection"
    # 결과물 출력 

    compiled_rules = compile_rules(yara_rules_directory)

    if compiled_rules:
        scan_exe_files(compiled_rules, target_directory)

    print(f"Scan results saved")

    