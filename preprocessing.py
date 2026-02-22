import re
from email import message_from_string
from email.utils import parsedate_to_datetime
from bs4 import BeautifulSoup

def extract_email_info(raw_email):
    # Parse the email content
    msg = message_from_string(raw_email)

    # Extract fields
    email_info = {
        "from": msg.get("From"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
        "return_path": msg.get("Return-Path"),
        "authentication_results": msg.get("ARC-Authentication-Results"),
    }

    # Get sender IP from Received headers
    received_headers = msg.get_all("Received")
    sender_ip = None
    if received_headers:
        for header in received_headers:
            ip_match = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', header)
            if ip_match:
                sender_ip = ip_match.group(1)
                break  # Use the first matched IP as the originating IP
    email_info["sender_ip"] = sender_ip

    # Extract and clean body (plain text, retaining URLs and clickable text)
    body_plain = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                charset = part.get_content_charset() or 'utf-8'  # Provide fallback charset
                body_content = part.get_payload(decode=True).decode(charset, errors="replace")
                # Parse HTML and keep URLs and content within tags
                soup = BeautifulSoup(body_content, "html.parser")

                # Remove all script and style tags
                for script_or_style in soup(["script", "style"]):
                    script_or_style.decompose()  # Remove scripts and CSS

                # Preserve the clickable text and URLs together
                for a in soup.find_all("a", href=True):
                    a.replace_with(f"{a.get_text()} ({a['href']})")

                body_plain = soup.get_text(separator=" ")  # Extract text with single-space separator
                break  # Stop at the first text-based part
    else:
        charset = msg.get_content_charset() or 'utf-8'  # Provide fallback charset
        body_content = msg.get_payload(decode=True).decode(charset, errors="replace")
        soup = BeautifulSoup(body_content, "html.parser")

        # Remove all script and style tags
        for script_or_style in soup(["script", "style"]):
            script_or_style.decompose()

        # Preserve the clickable text and URLs together
        for a in soup.find_all("a", href=True):
            a.replace_with(f"{a.get_text()} ({a['href']})")

        body_plain = soup.get_text(separator=" ")

    # Remove extra spaces and newlines
    body_plain = re.sub(r'\s+', ' ', body_plain).strip()
    email_info["body"] = body_plain

    # Optional: parse date to datetime
    parsed_date = parsedate_to_datetime(email_info["date"]) if email_info["date"] else None
    email_info["parsed_date"] = parsed_date

    return email_info


def preprocessing_content(raw_content):
    email_data = extract_email_info(raw_content)
    return email_data


# Example email
raw_email = """
Hello,

Please visit our website at https://example.com for more information.
If you have any questions, contact us at ple.org/help.

Best regards,
Example Team
"""

# result = preprocessing_content(raw_email)
# print(result)
