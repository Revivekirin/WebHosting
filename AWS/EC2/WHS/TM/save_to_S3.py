import boto3
import os
import re
from datetime import datetime

base_directory = "/home/ubuntu/WHS/TM/FILELIST"
bucket_name = 'codei-00926417c3e944373'

def find_latest_file(direcotry):
    file_pattern = re.compile(r'FILELIST_(\d{14})\.txt')
    files = [file for file in os.listdir(direcotry) if file_pattern.match(file)]

    if not files:
        return None
    
    latest_file = max(files, key=lambda x: file_pattern.match(x).group(1))
    return os.path.join(direcotry, latest_file)

s3 = boto3.client('s3')

latest_file_path = find_latest_file(base_directory)

if latest_file_path:
    with open(latest_file_path, 'r') as file:
        for line in file:
            file_name, file_path = map(str.strip, line.split(':'))

            current_datetime = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            s3_prefix = f'Malware_code/{current_datetime}/'

            local_directory_path = os.path.join(base_directory, os.path.dirname(file_path).strip())
            for local_file_name in os.listdir(local_directory_path):
                local_file_path = os.path.join(local_directory_path, local_file_name)
                s3_object_key = os.path.join(s3_prefix, file_name.strip(), local_file_name)
                s3.upload_file(local_file_path, bucket_name, s3_object_key)
                print(f'File {local_file_name} uploaded to S3 bucket {bucket_name} with key {s3_object_key}')

