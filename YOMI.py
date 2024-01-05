import json
import requests
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from datetime import datetime
import schedule
import os
from selenium.common.exceptions import TimeoutException
import shutil
import paramiko


result = []


def result_reset():
    global result
    result = []


def file_info_col():
    global result
    global json_file_name

    today = datetime.now().date()
    json_file_name = today.strftime('%Y%m%d') + ".json"

    # yomi 사이트 들어가기
    yomi_url = "https://yomi.yoroi.company/upload"  # yomi url
    driver = webdriver.Chrome()
    driver.get(yomi_url)
    time.sleep(2)

    # 메뉴 버튼 클릭
    menu_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.CLASS_NAME, "navigation__button")))
    menu_button.click()

    # login 클릭
    list_element = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CLASS_NAME, "navigation__list")))
    login_element = list_element.find_elements(By.TAG_NAME, 'li')[5]
    login_element.click()

    # login하기
    yomi_id = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, "mat-input-0")))
    yomi_id.send_keys("")
    yomi_pw = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, "mat-input-1")))
    yomi_pw.send_keys("")
    login_button = WebDriverWait(driver, 10).until(EC.element_to_be_clickable(
        (By.XPATH, '//button[@type="button" and text()="Sign In"]')))
    login_button.click()
    time.sleep(1)

    submission_api_url = "https://yomi.yoroi.company/api/sandbox/"
    response = requests.get(submission_api_url)
    data = response.json()

    if data[99] not in result:
        result += data
        print(result)
        with open(json_file_name, 'w') as file:
            json.dump(result, file, indent=2)
    driver.quit()


def duplicates_check(directory, sha256_hash):
    file_path = os.path.join(directory, sha256_hash + '.json')
    if os.path.exists(file_path):
        print(f"Duplicate: {sha256_hash}")
        return True
    return False


def sample_download_with_yomi():

    global json_file_name

    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_experimental_option("prefs", {
        "download.default_directory": os.getcwd(),  # 현재 작업 디렉토리로 설정
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
        "safebrowsing_for_trusted_sources_enabled": False,
        "safebrowsing.enabled": False
    })

    yomi_url = "https://yomi.yoroi.company/upload"
    driver = webdriver.Chrome(options=chrome_options)
    driver.get(yomi_url)
    time.sleep(2)

    menu_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.CLASS_NAME, "navigation__button")))
    menu_button.click()

    list_element = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CLASS_NAME, "navigation__list")))
    login_element = list_element.find_elements(By.TAG_NAME, 'li')[5]
    login_element.click()

    yomi_id = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, "mat-input-0")))
    yomi_id.send_keys("")
    yomi_pw = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, "mat-input-1")))
    yomi_pw.send_keys("")
    login_button = WebDriverWait(driver, 10).until(EC.element_to_be_clickable(
        (By.XPATH, '//button[@type="button" and text()="Sign In"]')))
    login_button.click()
    time.sleep(1)

    today = datetime.now().date()
    json_file_name = today.strftime('%Y%m%d')+".json"

    with open(json_file_name, 'r') as file:
        data = json.load(file)

    for i in range(0, len(data)):
        file_json = data[i]
        filename = file_json['filename']
        file_extension = filename.split(".")[-1]
        try:
            if file_extension.lower() == "exe":
                print(filename)
                id_1 = file_json['_id']
                id_2 = file_json["reports"][0]["_id"]
                download_url_string = "https://yomi.yoroi.company/report/"+id_1+"/"+id_2+"/overview"
                try:
                    driver.get(download_url_string)
                    file_information_elements = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.CLASS_NAME, "overview__details-file__list")))
                    real_filename = file_information_elements.find_elements(By.TAG_NAME, 'li')[
                        0]
                    real_filename_value = real_filename.find_element(
                        By.CLASS_NAME, "overview__details-file__item-value").text
                    hash_value = file_json['hash']
                    sha256_value = hash_value['sha256']
                    file_path_exe = os.path.join(
                        "", sha256_value[:2], sha256_value[2:4], sha256_value + '.exe')
                    file_path_json = os.path.join(
                        "", sha256_value[:2], sha256_value[2:4], sha256_value + '.json')

                    download = WebDriverWait(driver, 10).until(
                        EC.element_to_be_clickable((By.CLASS_NAME, "fas.fa-download")))
                    download.click()
                    time.sleep(1)
                except Exception:
                    driver.refresh()
                    continue
                try:
                    no_sample_button = WebDriverWait(driver, 15).until(
                        EC.element_to_be_clickable((By.CLASS_NAME, "mat-raised-button.mat-primary")))
                    no_sample_button.click()
                except TimeoutException:
                    directory = os.path.join(
                        "", sha256_value[:2], sha256_value[2:4])
                    if os.path.exists(directory):
                        print("exist directory")
                    else:
                        os.makedirs(directory, exist_ok=True)

                    current_file_path = os.path.join(
                        os.getcwd(), real_filename_value)
                    shutil.move(current_file_path, file_path_exe)

                    if not duplicates_check(os.path.join("yomi_file", sha256_value[:2], sha256_value[2:4]), sha256_value):
                        with open(file_path_json, 'w') as json_file:
                            json.dump(file_json, json_file)
                    time.sleep(1)
                    driver.refresh()
                    continue
                except Exception:
                    continue
        except IndexError:
            print("IndexError")
            continue
    driver.quit()


def upload_directory(local_path, remote_user, remote_ip, remote_path, private_key_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(remote_ip, username=remote_user, key_filename=private_key_path)

    try:
        with ssh.open_sftp() as sftp:
            for root, dirs, files in os.walk(local_path):
                for file in files:
                    if file == ".DS_Store":
                        continue
                    local_file_path = os.path.join(root, file)
                    prefix = file[:2]
                    postfix = file[2:4]
                    remote_dir_path1 = os.path.join(
                        remote_path, prefix)

                    remote_dir_path2 = os.path.join(
                        remote_path, prefix, postfix)

                    try:
                        if sftp.stat(remote_dir_path1):
                            print("remote_dir_path1 exist")
                            try:
                                if sftp.stat(remote_dir_path2):
                                    print("remote_dir_path2 exist")
                            except IOError:
                                sftp.mkdir(remote_dir_path2)
                    except IOError:
                        sftp.mkdir(remote_dir_path1)
                        sftp.mkdir(remote_dir_path2)

                    remote_file_path = os.path.join(remote_dir_path2, file)
                    print(remote_file_path)
                    sftp.put(local_file_path, remote_file_path)
                    print("Upload success")
    except Exception:
        print("Upload fail")
    finally:
        ssh.close()


def upload_to_aws():
    local_path = ""
    remote_user = ""
    elastic_ip = ""
    remote_path = ""
    private_key_path = ""

    upload_directory(local_path, remote_user, elastic_ip,
                     remote_path, private_key_path)


def delete_yomi_subdirectories():
    yomi_path = ""
    try:
        shutil.rmtree(yomi_path)
    except Exception:
        print("Delete fail")


schedule.every().day.at("00:00").do(result_reset)
schedule.every(20).minutes.do(file_info_col)
schedule.every().day.at("23:00").do(delete_yomi_subdirectories)
schedule.every().day.at("23:50").do(sample_download_with_yomi)
schedule.every().day.at("12:00").do(upload_to_aws)


while True:
    schedule.run_pending()
    time.sleep(1)
