# Sensitive Data Finder
This tool is designed to search for sensitive information on web pages using regular expressions. The program performs multi-threaded scanning, allowing for rapid and efficient checks across multiple URLs.

## Features:
- Search using predefined regular expressions.
- Multi-threaded scanning with an option to define the number of threads.
- Delay option between requests to prevent potential rate-limiting.
- Capability to write results to a file.

## Installation:
- Ensure you have Python 3 installed.
- Clone the repository:
```
git clone <your repository link>
cd <name of your repository directory>
```
## Usage:
```
python3 main.py -t <number of threads> -d <delay between requests> -i <input URL file or a single URL> -o <output results file>
```
## Example:
```
python3 main.py -t 5 -d 1 -i urls.txt -o results.txt
```

## Parameters:
- `-t, --threads` - number of threads (default is 10).
- `-d, --delay` - delay between requests in seconds (default is 1 second).
- `-i, --input` - input file containing URLs or a standalone URL (default is urls.txt).
- `-o, --output` - file to write results to (default is results.txt).
