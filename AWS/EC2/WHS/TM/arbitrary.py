import os
from datetime import datetime

def create_line_count_file(file_list_paths):
    total_exe_count = 0

    for file_list_path in file_list_paths:
        with open(file_list_path, 'r') as file_list:
            for line in file_list:
                _, file_path = line.strip().split(" : ")
                if file_path.lower().endswith('.exe'):
                    total_exe_count += 1


    day_count_path = os.path.join("/home/ubuntu/WHS/TM/count", f"2024103_count.txt")

    with open(day_count_path, 'w') as day_count_file:
        day_count_file.write(str(total_exe_count))

file_list_paths = [
    "/home/ubuntu/WHS/TM/FILELIST/FILELIST_20240103082001.txt",
]

create_line_count_file(file_list_paths)