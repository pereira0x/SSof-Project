#!/bin/bash

# Run this as:
# $ ./run_test.sh [--stop] [--keep]
# --stop: Stop the script if a test fails
# --keep: Keep the validation_output.txt and output.json files after the script finishes
# Set default values for optional arguments
stop_script=false
keep_files=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --stop)
        stop_script=true
        shift
        ;;
        --keep)
        keep_files=true
        shift
        ;;
        *)
        echo "Unknown option: $key"
        exit 1
        ;;
    esac
done

# Get the list of .js files in the slices folder and sort them
js_files=$(find my_slices -type f -name "*.js" | sort)

# Loop through each .js file
for file in $js_files; do
    # Get the corresponding patterns file
    patterns_file="${file%.js}.patterns.json"
    output_file="${file%.js}.output.json"
    echo "Running test for $file with patterns file $patterns_file and output file $output_file"
    # Run the js_analyser.py command
    python3 js_analyser.py "$file" "$patterns_file"
    python3 validate.py -o output.json -t "$output_file" > validation_output.txt

    # Check if the output contains the strings "MISSING FLOWS" or "WRONG FLOWS"
    if grep -qE "MISSING FLOWS|WRONG FLOWS" validation_output.txt; then
        echo -e "\e[31m$file failed\e[0m"
        if $stop_script; then
            break
        fi
    else
        echo -e "\e[32m$file passed\e[0m"
    fi
done

# Remove validation_output.txt and output.json if --keep option is not provided
if ! $keep_files; then
    rm validation_output.txt output.json
fi
