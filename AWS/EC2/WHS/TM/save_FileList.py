import os
from datetime import datetime

base_directory = '/home/ubuntu/WHS/TM'
main_file_list_path = "/home/ubuntu//WHS/TM/FILELIST/MainFileList.txt"
daily_count_csv_path = "/home/ubuntu/WHS/TM/DailyCount.csv"


def update_txt_file(file_name, file_path, file_list_path):
    if not os.path.exists(file_list_path):
        with open(file_list_path, 'w'): pass
        
    with open(file_list_path, 'a') as file:
        file.write(f"{file_name} : {file_path}\n")


def update_daily_count_csv(daily_count_csv_path, day, total_exe_count):
    if not os.path.exists(daily_count_csv_path):
        with open(daily_count_csv_path, 'w') as csv_file:
            csv_file.write("Day,Count\n")

    with open(daily_count_csv_path, 'a') as csv_file:
        csv_file.write(f"{day},{total_exe_count}\n")


def create_line_count_file(file_list_path):
    total_exe_count = 0

    with open(file_list_path, 'r') as file_list:
        for line in file_list:
            _, file_path = line.strip().split(" : ")
            if file_path.lower().endswith('.exe'):
                total_exe_count += 1

    day = datetime.now().strftime("%Y%m%d")
    day_count_path = os.path.join("/home/ubuntu/WHS/TM/count", f"{day}.txt")

    with open(day_count_path, 'w') as day_count_file:
        day_count_file.write(str(total_exe_count))


def automate_analyze(base_directory):
    existing_files = set()
    with open(main_file_list_path, 'r') as main_file_list:
        existing_files = {line.strip() for line in main_file_list.readlines()}
            

    timestamp = datetime.now().strftime("%Y%m%d")
    file_list_directory = "/home/ubuntu/WHS/TM/FILELIST/"
    file_list_path = os.path.join(file_list_directory,f"FILELIST_{timestamp}.txt")

    total_exe_count = 0

    for root, dirs, files in os.walk(base_directory):
        for file in files:
            if file.endswith('exe'):
                file_path = os.path.join(root, file)
                entry = f"{file} : {file_path}"

                if entry not in existing_files:
                    update_txt_file(file, file_path, main_file_list_path)
                    update_txt_file(file, file_path, file_list_path)
                    total_exe_count +=1 

    day = datetime.now().strftime("%Y%m%d")
    create_line_count_file(file_list_path)
    update_daily_count_csv(daily_count_csv_path, day, total_exe_count)


automate_analyze(base_directory)


