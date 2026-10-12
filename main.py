
import json
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

REPORTS_DIR = Path("reports")


def normalize_url(url):
    """Validate and normalize an HTTP or HTTPS URL."""
    url = url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    parsed = urlparse(url)

    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("Please enter a valid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported.")

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Please enter a valid port number.") from error

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Please enter a valid port number.")

    return urlunparse(parsed)


def check_website(url):
    """Fetch a website and inspect its response."""
    url = normalize_url(url)

    request = Request(
        url,
        headers={"User-Agent": "StudentWebsiteChecker/1.0"}
    )

    try:
        with urlopen(request, timeout=10) as response:
            headers = response.headers
            status = response.status
            final_url = response.geturl()

    except HTTPError as error:
        headers = error.headers
        status = error.code
        final_url = error.geturl()

    except (URLError, TimeoutError, ssl.SSLError, OSError) as error:
        raise ConnectionError(
            f"Could not reach the website: {error}"
        ) from error

    header_results = {}

    for header in SECURITY_HEADERS:
        value = headers.get(header)

        header_results[header] = {
            "present": bool(value),
            "value": value if value else None,
        }

    return {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "requested_url": url,
        "final_url": final_url,
        "http_status": status,
        "https_used": final_url.lower().startswith("https://"),
        "security_headers": header_results,
        "note": (
            "Missing headers are observations, not proof that a website "
            "is vulnerable. This is a basic informational check, "
            "not a full security audit."
        ),
    }


def format_report(report):
    """Format results as readable text."""
    lines = [
        "--- Website Check Report ---",
        f"Checked at (UTC): {report['checked_at_utc']}",
        f"Requested URL:    {report['requested_url']}",
        f"Final URL:        {report['final_url']}",
        f"HTTP status:      {report['http_status']}",
        f"HTTPS used:       {report['https_used']}",
        "",
        "Security-related response headers:",
    ]

    for name, details in report["security_headers"].items():
        if details["present"]:
            lines.append(f"[PRESENT] {name}: {details['value']}")
        else:
            lines.append(f"[MISSING] {name}")

    lines.extend(["", f"Note: {report['note']}"])

    return "\n".join(lines)


def save_reports(report):
    """Save JSON and text reports."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"website_report_{timestamp}"

    json_path = REPORTS_DIR / f"{base_name}.json"
    text_path = REPORTS_DIR / f"{base_name}.txt"

    json_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    text_path.write_text(
        format_report(report),
        encoding="utf-8"
    )

    return json_path, text_path


def main():
    target = input(
        "Enter a website URL you own or are authorised to check: "
    )

    try:
        report = check_website(target)

        print()
        print(format_report(report))

        json_path, text_path = save_reports(report)

        print("\nReports saved:")
        print(f"JSON: {json_path}")
        print(f"Text: {text_path}")

    except ValueError as error:
        print(f"Input error: {error}")

    except ConnectionError as error:
        print(f"\n{error}")


if __name__ == "__main__":
    main()
