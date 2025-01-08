#!/bin/bash

# Run this as:
# $ ./run_test.sh [--stop] [--keep] [--slice=<name>.js]
# --stop: Stop the script if a test fails
# --keep: Keep the validation_output.txt and output.json files after the script finishes
# --slice=<name>.js: Run a single file

# Set default values for optional arguments
stop_script=false
keep_files=false
single_file=""

# Initialize counters
tests_passed=0
tests_failed=0

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
        --slice=*.js)
        single_file="${key#*=}"
        shift
        ;;
        *)
        echo "Unknown option: $key"
        exit 1
        ;;
    esac
done

# Get the list of .js files in the slices folder and sort them
if [ -z "$single_file" ]; then
    js_files=$(find my_slices -type f -name "*.js" | sort)
else
    js_files="my_slices/$single_file"
fi

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
    if grep -qE "MISSING FLOWS|WRONG FLOWS|wrong type" validation_output.txt; then
        echo -e "\e[31m$file failed\e[0m"
        tests_failed=$((tests_failed+1))
        if $stop_script; then
            break
        fi
    else
        echo -e "\e[32m$file passed\e[0m"
        tests_passed=$((tests_passed+1))
    fi
done

# Remove validation_output.txt and output.json if --keep option is not provided
if ! $keep_files; then
    rm validation_output.txt output.json
fi

# Display test results
echo -e "\nTest Results:"
echo -e "Tests Passed: \e[32m$tests_passed\e[0m"
echo -e "Tests Failed: \e[31m$tests_failed\e[0m"
