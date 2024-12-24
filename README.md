# Phishing Indicator

## Description

This Python script implements a tool to check for potential phishing URLs. It analyzes URLs and their contents to detect common phishing indicators, providing a simple yet effective way to identify malicious links.

## Features

- **URL Cleaning**: Ensures the URL has the correct scheme (http/https).
- **Domain Extraction**: Extracts the root domain using publicsuffix2.
- **SSL Validation**: Validates the SSL certificate of the domain.
- **Phishing Indicator Detection**: Checks for common phishing indicators in the URL.
- **Content Analysis**: Analyzes page content for phishing phrases and urgency phrases.
- **User Interaction**: Accepts multiple URLs from user input and processes each one.

## How It Works

1. **URL Cleaning**: Ensures the URL has a scheme (http/https) using the `clean_url` function.
2. **Domain Extraction**: Extracts the root domain using the `extract_root_domain` function.
3. **SSL Validation**: Validates the SSL certificate of the domain using the `validate_ssl` function.
4. **Phishing Indicator Detection**: Checks for common phishing indicators in the URL using predefined lists.
5. **Content Analysis**: Analyzes the page content for phishing and urgency phrases using BeautifulSoup and predefined lists.
6. **User Interaction**: Accepts multiple URLs from user input and processes each one.

## Code Explanation

- **`clean_url(url)`**: Ensures the URL has a scheme (http/https).
- **`extract_root_domain(url)`**: Extracts the root domain using publicsuffix2.
- **`validate_ssl(domain)`**: Validates the SSL certificate of the domain.
- **`is_phishing_url(url)`**: Checks if the given URL is a phishing link by performing various checks (domain, phishing indicators, SSL validation, and content analysis).

## Usage

### Clone the Repository
 
    git clone https://github.com/Mohansaikrishna1601/Brainwave_Matrix_Intern-Task01.git
    cd Brainwave_Matrix_Intern-Task01

### Install Dependencies:
   Use the following command to install the required libraries listed in requirements.txt:
                       
    pip install -r requirements.txt


### Run the Script
    python phishing_indicator.py

### Example
Enter URLs separated by a comma: http://example.com, http://test.com

Checking URL: http://example.com
[Domain] Extracted domain: example.com
[SSL] Validating SSL for: example.com
[SSL] Could not validate SSL for example.com: hostname 'example.com' doesn't match 'example.com'
[Phishing Indicator] Suspicious keyword found in URL: http://example.com
❌ The URL http://example.com is likely a phishing link.

Checking URL: http://test.com
[Domain] Extracted domain: test.com
[SSL] Validating SSL for: test.com
[SSL] Valid SSL certificate for domain: test.com
✅ The URL http://test.com seems safe.


### Author
  Mohan Sai Krishna G M

