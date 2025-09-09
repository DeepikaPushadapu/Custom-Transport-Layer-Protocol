#!/bin/bash

# Define the directory containing the ip_port.txt files
directory="."

# Define the content file
content_file="content.txt"

# Loop through each ip_port.txt file
for file in "$directory"/*.*.*.*_*.txt; do

    # Print the filename
    echo "Comparing file: $file, with $content_file"

    # Run diff command and display output
    diff "$file" "$content_file"
done
