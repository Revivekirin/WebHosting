import subprocess
import datetime
import os

def count_exe_files(directory='../collection'):
    try:
        all_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(directory) for f in filenames]
        exe_files = [file for file in all_files if file.lower().endswith('.exe')]
        return len(exe_files)
    except Exception:
        return None

def main():
    today = datetime.date.today()
    yesterday = today - datetime.timedelta(days=1)
    yesterday_exe_count = 0
    try:
        with open(f'{yesterday}_daily_count.txt', 'r') as file:
            yesterday_exe_count = int(file.read())
    except FileNotFoundError:
        pass
    today_exe_count = count_exe_files()

    if today_exe_count is not None:
        print(f"Total exe file count is {today_exe_count}")
        print(f"Today's exe file count is {(today_exe_count - yesterday_exe_count)}")

        with open(f'{today}_daily_count.txt', 'w') as file:
            file.write(str(today_exe_count- yesterday_exe_count))

if __name__ == "__main__":
    main()
