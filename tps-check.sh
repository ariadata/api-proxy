#!/bin/bash

# Set the URL
url="localhost:3003/proxy/example-path/"

# Set the number of requests (default is 10)
count=${1:-100}

# Loop through the specified number of requests
for i in $(seq 1 $count); do
  # Get the current timestamp
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")

  # Make the request and capture the JSON response
  response=$(curl -s "$url")

  # Extract the url value using jq
  extracted_url=$(echo "$response" | jq -r '.url')

  # Print the timestamp and extracted URL
  echo "$timestamp $extracted_url"
done