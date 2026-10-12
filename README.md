

\# Website Security Audit \& Reporting Tool



A Python command-line tool that checks a website's HTTP response and reports the presence or absence of five common security-related response headers. It exports results as JSON and readable text files.



\## Requirements

\- Python 3.10 or newer

\- Internet connection

\- No third-party packages required



\## Usage



Run `py main.py` and enter a domain such as `example.com` or a full HTTPS URL.



Reports are saved in the `reports` directory.



\## Headers checked

\- Strict-Transport-Security

\- Content-Security-Policy

\- X-Content-Type-Options

\- X-Frame-Options

\- Referrer-Policy



\## Limitations



This is an informational check, not a full security audit or vulnerability scanner. A missing header alone does not prove that a website is vulnerable. Results reflect the response received at the time of the check. The tool does not crawl pages, test exploits, or scan ports.



Only check websites you own or are authorised to assess.



