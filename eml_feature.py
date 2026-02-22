import re
from email import message_from_file
from email import message_from_string
from email.utils import parsedate_to_datetime
from bs4 import BeautifulSoup
from email.parser import BytesParser
from email import policy

def extract_eml(file):
    """
    Extracts and processes content from a .eml file.

    Args:
        file_path (str): The path to the .eml file.

    Returns:
        dict: A dictionary containing the extracted fields.
    """
  
    msg = message_from_string(file)

    # Extract fields
    from_email = msg.get("From")
    subject = msg.get("Subject")
    date = msg.get("Date")
    message_id = msg.get("Message-ID")
    return_path = msg.get("Return-Path")
    authentication_results = msg.get("ARC-Authentication-Results")

    # Get sender IP from Received headers
    received_headers = msg.get_all("Received")
    sender_ip = None
    for header in received_headers:
        ip_match = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', header)
        if ip_match:
            sender_ip = ip_match.group(1)
            break  # Use the first matched IP as the originating IP

    # Extract and clean body (plain text, retaining URLs and clickable text)
    body_plain = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                charset = part.get_content_charset() or 'utf-8'  # Fallback to 'utf-8' if charset is None
                body_content = part.get_payload(decode=True)
                if body_content is not None:
                    body_content = body_content.decode(charset, errors="replace")
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
        charset = msg.get_content_charset() or 'utf-8'
        body_content = msg.get_payload(decode=True)
        if body_content is not None:
            body_content = body_content.decode(charset, errors="replace")
        
        # Remove all script and style tags
        soup = BeautifulSoup(body_content, "html.parser")
        for script_or_style in soup(["script", "style"]):
            script_or_style.decompose()

        # Preserve the clickable text and URLs together
        for a in soup.find_all("a", href=True):
            a.replace_with(f"{a.get_text()} ({a['href']})")

        body_plain = soup.get_text(separator=" ")

    # Remove extra spaces and newlines
    body_plain = re.sub(r'\s+', ' ', body_plain).strip()

    # Optional: parse date to datetime
    if date:
        try:
            parsed_date = parsedate_to_datetime(date)
        except (TypeError, ValueError) as e:
            parsed_date = None  # Assign a fallback if parsing fails
    else:
        parsed_date = None

    return {
        "from_email": from_email,
        "subject": subject,
        "date": parsed_date,
        "message_id": message_id,
        "return_path": return_path,
        "authentication_results": authentication_results,
        "sender_ip": sender_ip,
        "body_plain": body_plain
    }

def extract_eml_body(file):
    # Parse the EML file
    # with open(file_path, 'rb') as f:
    #     msg = BytesParser(policy=policy.default).parse(f)

    #Change to take file as input
    msg = BytesParser(policy=policy.default).parse(file)
    # Get the email subject
    subject = msg.get('subject', '')  # Empty string if no subject

    # Traverse all parts of the email to find HTML content
    body = None
    if msg.is_multipart():
        for part in msg.walk():  # Use .walk() to traverse all parts
            if part.get_content_type() == "text/html":
                body = part.get_payload(decode=True).decode(part.get_content_charset())
                break
    else:
        if msg.get_content_type() == "text/html":
            body = msg.get_payload(decode=True).decode(msg.get_content_charset())

    if not body:
        return "No HTML content found in the email."

    # Process HTML content with BeautifulSoup
    soup = BeautifulSoup(body, "html.parser")

    # Find all image tags and replace them with their alt text
    for img in soup.find_all('img', alt=True):
        alt_text = img['alt'].strip()
        if alt_text:
            # Replace the <img> tag with its alt text
            img.replace_with(alt_text)

    # Remove non-visible or metadata tags
    for tag in soup(['title', 'style', 'script', 'head', 'meta']):
        tag.decompose()  # Remove tag and its contents
    
    # Remove empty tags or those with only whitespace
    for tag in soup.find_all():
        if not tag.get_text(strip=True):  # Check if tag's text is empty after stripping whitespace
            tag.decompose()

    # Find all links (anchor tags) and replace them with their text + URL
    for link in soup.find_all('a', href=True):
        link_text = link.get_text().strip() or "Link"
        href = link['href']
        # Replace link with the text + URL format
        link.replace_with(f"{link_text} ({href})")

    # Strip all HTML but keep URLs and their associated text
    text = soup.get_text()

    # Remove large spaces, including newlines and multiple spaces, and replace with a single space
    text = re.sub(r'\s+', ' ', text).strip()

    # Prepend the subject at the beginning with a single space in between
    if subject:
        full_text = f"{subject} {text}"
    else:
        full_text = text

    # Return the processed text
    return full_text



# Example usage
