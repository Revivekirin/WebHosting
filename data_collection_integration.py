import json
import requests
import pyzipper
from io import BytesIO
import os
from jq import jq

import API_Key


def duplicates_check(directory, sha256_hash):
    file_path = os.path.join(directory, sha256_hash + '.json')
    
    if os.path.exists(file_path):
        print(f"Duplicate: {sha256_hash}")
        return True
    
    os.makedirs(directory, exist_ok=True)
    return False



def get_urlhaus_json(sha256_hash):
    url = 'https://urlhaus-api.abuse.ch/v1/payload/'
    data = {'sha256_hash': sha256_hash}

    try:
        response = requests.post(url, data=data)

        if response.status_code == 200:
            json_response = response.json()
            file_path = os.path.join('../collection', sha256_hash[:2], sha256_hash[2:4], sha256_hash + '.json')
            with open(file_path, 'w') as json_file:
                json.dump(json_response, json_file, indent=2)

        else:
            print(f"Error: {response.status_code}")

    except Exception as e:
        print(f"An error occurred: {e}")



def download_urlhaus_sample(sha256_hash):

    url = 'https://urlhaus-api.abuse.ch/v1/download/{}/'.format(sha256_hash)
    ZIP_PASSWORD = b'infected'

    response = requests.get(url)

    if response.status_code == 200:
        try:
            with pyzipper.AESZipFile(BytesIO(response.content)) as zf:
                zf.pwd = ZIP_PASSWORD
                file_path = os.path.join('../collection', sha256_hash[:2], sha256_hash[2:4])

                # extractall 대신 extract를 사용하여 특정 파일만 추출합니다.
                zf.extractall(file_path)

                # 추출된 파일에 ".exe"를 추가합니다.
                os.rename(os.path.join(file_path, sha256_hash), os.path.join(file_path, sha256_hash+'.exe'))

                print("Sample \"" + sha256_hash + "\" downloaded and unpacked.")

        except pyzipper.BadZipFile:
            print(f"Warning: {sha256_hash} is not a valid ZIP file. Downloading the file as is.")
            
            # ZIP 파일이 아니라면 그냥 다운로드
            file_path = os.path.join('../collection', sha256_hash[:2], sha256_hash[2:4])
            with open(os.path.join(file_path, sha256_hash+'.exe'), 'wb') as file:
                file.write(response.content)
                cnt += 1
                print("Sample \"" + sha256_hash + "\" downloaded.")
    else:
        print(f"Error: {response.status_code}")



def get_urlhaus_sample():
    url = 'https://urlhaus-api.abuse.ch/v1/payloads/recent/'

    try:
        response = requests.get(url)

        if response.status_code == 200:
            json_response = response.content.decode("utf-8", "ignore")
            samples = jq(".payloads[]").transform(text=json_response, multiple_output=True)

            for sample in samples:
                if sample.get('file_type') == 'exe':
                    sha256_hash = sample.get('sha256_hash')            
                    
                    # 중복 체크 및 디렉토리로 이동
                    if not duplicates_check(os.path.join('../collection', sha256_hash[:2], sha256_hash[2:4]), sha256_hash):
                        download_urlhaus_sample(sha256_hash)
                        get_urlhaus_json(sha256_hash)
                        print("Sample \"" + sha256_hash + "\" downloaded and save JSON file.")

        else:
            print(f"Error: {response.status_code}")

    except Exception as e:
        print(f"An error occurred: {e}")




def get_malware_json(sha256_hash):
    data = {'query': 'get_info', 'hash': sha256_hash}
    response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, allow_redirects=True)


    file_path = os.path.join('../collection', sha256_hash[:2], sha256_hash[2:4], sha256_hash + '.json')
    with open(os.path.join(file_path), 'wb') as json_file:
        json_file.write(response.content)


def download_malware_sample(sha256_hash):

    headers = {'API-KEY': API_Key.MalwareBazaarAPI}

    ZIP_PASSWORD = b'infected'

    data = {'query': 'get_file', 'sha256_hash': sha256_hash}
    response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=2, headers=headers, allow_redirects=True)

    if 'file_not_found' in response.text:
        print("Error: file not found")

    else:
        with pyzipper.AESZipFile(BytesIO(response.content)) as zf:
            zf.pwd = ZIP_PASSWORD
            
            file_path = os.path.join('../collection', sha256_hash[:2], sha256_hash[2:4])
            zf.extractall(file_path)

            print("Sample \"" + sha256_hash + "\" downloaded and unpacked.")


def get_malware_sample():

    headers = {'API-KEY': API_Key.MalwareBazaarAPI}
    
    data = {
        'query': 'get_recent',
        'selector': 'time',
    }

    response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=2, headers=headers)
    json_response = response.content.decode("utf-8", "ignore")

    # jq를 사용하여 필요한 해시들만 추출 (sha256_hash, file_type)
    hashes = jq(".data[].sha256_hash").transform(text=json_response, text_output=True).replace('"', '').split('\n')
    file_types = jq(".data[].file_type").transform(text=json_response, text_output=True).replace('"', '').split('\n')

    for sha256_hash, file_type in zip(hashes, file_types):
        if file_type == 'exe':
            # 중복 체크 및 디렉토리로 이동
            if not duplicates_check(os.path.join('../collection', sha256_hash[:2], sha256_hash[2:4]), sha256_hash):
                download_malware_sample(sha256_hash)
                get_malware_json(sha256_hash)


if __name__ == "__main__":

    try:
        get_malware_sample()
    except Exception as e:
        print(f"An error occurred: {e}")

    try:
        get_urlhaus_sample()
    except Exception as e:
        print(f"An error occurred: {e}")

