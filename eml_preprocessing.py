def preprocess_eml(file_content):
    # Preprocess the .eml file content and extract necessary fields
    msg = message_from_bytes(file_content)
    
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
            break

    # Extract and clean body (plain text, retaining URLs and clickable text)
    body_plain = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" or content_type == "text/html":
                body_content = part.get_payload(decode=True).decode(part.get_content_charset(), errors="replace")
                soup = BeautifulSoup(body_content, "html.parser")
                
                # Remove scripts and CSS
                for script_or_style in soup(["script", "style"]):
                    script_or_style.decompose()

                for a in soup.find_all("a", href=True):
                    a.replace_with(f"{a.get_text()} ({a['href']})")

                body_plain = soup.get_text(separator=" ")
                break
    else:
        body_content = msg.get_payload(decode=True).decode(msg.get_content_charset(), errors="replace")
        soup = BeautifulSoup(body_content, "html.parser")
        
        # Remove scripts and CSS
        for script_or_style in soup(["script", "style"]):
            script_or_style.decompose()

        for a in soup.find_all("a", href=True):
            a.replace_with(f"{a.get_text()} ({a['href']})")

        body_plain = soup.get_text(separator=" ")

    # Remove extra spaces and newlines
    body_plain = re.sub(r'\s+', ' ', body_plain).strip()

    # Return extracted data
    return {
        "from_email": from_email,
        "sender_ip": sender_ip,
        "subject": subject,
        "message_id": message_id,
        "return_path": return_path,
        "authentication_results": authentication_results,
        "body_plain": body_plain,
    }
