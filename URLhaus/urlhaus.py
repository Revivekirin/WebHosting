import json
import requests
import pyzipper
from io import BytesIO
import os
from jq import jq


def get_json_file(sha256_hash):

    url = 'https://urlhaus-api.abuse.ch/v1/payload/'
    data = {'sha256_hash': sha256_hash}

    try:
        # HTTP POST 요청 보내기
        response = requests.post(url, data=data)

        # 응답 확인
        if response.status_code == 200:
            json_response = response.json()
            with open(os.path.join('./malicious', sha256_hash + '.json'), 'w') as json_file:
                json.dump(json_response, json_file, indent=2)

        else:
            print(f"Error: {response.status_code}")

    except Exception as e:
        print(f"An error occurred: {e}")


def download_sample(sha256_hash):

    url = 'https://urlhaus-api.abuse.ch/v1/download/{}/'.format(sha256_hash)
    ZIP_PASSWORD = b'infected'
        
    response = requests.get(url)

    # 응답 확인
    if response.status_code == 200:
        # ZIP 파일을 메모리에 로드
        with pyzipper.AESZipFile(BytesIO(response.content)) as zf:
            zf.pwd = ZIP_PASSWORD
            # 지정된 파일 이름으로 파일 저장
            zf.extractall("./malicious")
            print("Sample \"" + sha256_hash + "\" downloaded and unpacked.")

    else:
        print(f"Error: {response.status_code}")


def get_sample():

    url = 'https://urlhaus-api.abuse.ch/v1/payloads/recent/'

    try:
        # URL에서 데이터 가져오기
        response = requests.get(url)

        # 응답 확인
        if response.status_code == 200:
            json_response = response.content.decode("utf-8", "ignore")
            samples = jq(".payloads[]").transform(text=json_response, multiple_output=True)

            for sample in samples:
                if sample.get('file_type') == 'exe' :
                    download_sample(sample.get('sha256_hash'))
                    get_json_file(sample.get('sha256_hash'))

        else:
            print(f"Error: {response.status_code}")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    get_sample()
