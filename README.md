# vuln-Server-Side-Template-Injection-Detector
Detects potential Server-Side Template Injection (SSTI) vulnerabilities by injecting common template expressions and analyzing the response for a computed result. The target is fetched once without a payload first, and a result is reported only when the computed marker appears in a payload response and was absent from that baseline. Payload text is never run by the detector itself: each expected marker is computed from the payload's own numbers through an arithmetic whitelist. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowGuardAI/vuln-server-side-template-injection-detector`

## Usage
`./vuln-server-side-template-injection-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-d`: Data to send in the request body (e.g., 
- `-H`: Custom header(s) to send with the request (e.g., 'Content-Type: application/json'). Can be specified multiple times.
- `-m`: HTTP method to use (GET or POST). Defaults to GET.
- `--timeout`: Request timeout in seconds. Defaults to 10.
- `--user-agent`: Custom User-Agent header.

## License
Copyright (c) ShadowGuardAI
