#!/bin/bash

#Specifiy the S3 bucket and file name
S3_BUCKET = "codei-00926417c3e944373"
S3_PATH = '/file_urls.txt'

# Remove existing file_urls.json from the local directory
rm -f file_urls.txt

# Remove existing file_urls.json from the S3 bucket
aws s3 rm "s3://${S3_BUCKET}/${S3_PATH}"

# Run the AWS CLI command to create a new file_urls.json
aws s3 ls s3://codei-00926417c3e944373 --recursive --output json > file_urls.txt

# Upload the new file_urls.json to the S3 bucket
aws s3 cp file_urls.txt "s3://${S3_BUCKET}/"