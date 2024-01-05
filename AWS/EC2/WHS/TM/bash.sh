#!/bin/bash
# Change to the directory where your files are located
cd /home/ubuntu/WHS/TM

# Run your code
python3 save_FileList.py

python3 print_json.py

python3 save_to_S3.py



S3_BUCKET = "codei-00926417c3e944373"
S3_PATH = '/DailyCount.csv'

rm -f DailyCount.csv

aws s3 rm "s3://${S3_BUCKET}/${S3_PATH}"

# Upload the new file_urls.json to the S3 bucket
aws s3 cp /home/ubuntu/WHS/TM/count/DailyCount.csv "s3://${S3_BUCKET}/"