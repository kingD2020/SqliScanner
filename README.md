# SqliScanner

**SqliScanner** is an advanced SQL injection testing tool that automates the process of detecting SQL injection vulnerabilities in web applications. **Please use this tool only on websites for which you have explicit permission to test.**

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Payloads](#payloads)
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)

## Features
- Comprehensive SQL injection testing with a variety of payloads.
- Multi-threaded execution for faster testing.
- Detailed logging of results and errors.
- Outputs results to a text file and configuration details to a JSON file.

## Requirements
- Python 3.x
- Required libraries can be installed via pip.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kingD2020/SqliScanner.git
   cd SqliScanner
   pip install requests
   python Sqli.py

   ````

## View the results: 
The results of the scan will be logged in an output file named output.txt, and the configuration details will be saved in config_results.json. You can open these files to analyze the findings.


## Logging

The scanner logs all activity in sql_injection_test.log. This includes the response status for each payload and any detected errors or successes.
Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Ensure you include tests for any new features.


## License

This project is licensed under the MIT License - see the LICENSE file for details.



   


