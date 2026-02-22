import re
import pandas as pd
from urllib.parse import urlparse
import whois
import socket
import matplotlib.pyplot as plt
import ssl
import socket
import requests
import dns
import dns.resolver
from difflib import SequenceMatcher
from threading import Thread
from datetime import datetime

page_ranking_df = pd.read_csv('data\\top10milliondomains.csv')
page_ranking_df.columns = page_ranking_df.columns.str.strip()  # Clean column names
page_ranking_df.set_index('Domain', inplace=True)  # Set index to 'Domain'

# Fetch the valid TLDs from the Public Suffix List
valid_tlds_response = requests.get('https://raw.githubusercontent.com/publicsuffix/list/refs/heads/master/public_suffix_list.dat')
valid_tlds = set()

# Load the list of URL shorteners from the text file
url_shorteners_url = "https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/refs/heads/master/list"
url_shortener_response = requests.get(url_shorteners_url)

# Load the suspicious TLDs list once at the start
tlds_url = 'https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_tlds_list.csv'
suspicious_tlds_df = pd.read_csv(tlds_url)
suspicious_tlds = set(suspicious_tlds_df['metadata_tld'].str.lower()) # Convert the TLD list to a set for faster lookup

#  __________________________________________________________________________________
# |                                                                                  |
# |                                 OLD FEATURES                                     |
# |                                                                                  |
# |__________________________________________________________________________________|


def get_open_page_rank(url):
    """Get the Open Page Rank for the given URL domain, return 10,000,000 if not found."""
    # Load page ranking dataset
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Prepend a scheme

    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]
    if domain in page_ranking_df.index:
        return page_ranking_df.loc[domain, 'Open Page Rank']
    return 0

def get_url_length(url): 
    if get_path_length(url) > 0:
        return get_domain_length(url) + get_path_length(url) + 1
    return get_domain_length(url) + get_path_length(url)

def get_domain_length(url):
    # Add http if missing to ensure urlparse can handle it correctly
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Extract the netloc (domain part)
    domain = urlparse(url).netloc
    
    # Remove "www." if it's present at the start
    if domain.startswith('www.'):
        domain = domain[4:]
    
    return len(domain)

def is_domain_ip(url):
    domain = urlparse(url).hostname or url
    return int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain)))

def get_char_continuation_rate(url):
    sequences = re.findall(r'[a-zA-Z]+|\d+|[^\w\s]', url)
    total_sequence_length = sum(len(seq) for seq in sequences)
    return total_sequence_length / len(url) if len(url) > 0 else 0

# def get_tld_length(url): # Old version of get_tld_length (DO NOT USE)
#     # Check if the URL has a scheme; if not, prepend 'http://' for parsing
#     if not url.startswith(('http://', 'https://')):
#         url = 'https://' + url  # Adding http for parsing purposes

#     hostname = urlparse(url).hostname  # Extract hostname using urlparse
#     if hostname:
#         hostname_parts = hostname.split('.')
#         return len(hostname_parts[-1])  # Length of the last part is the TLD length
#     return 0  # Return 0 if hostname is None

def get_num_subdomains(url):
    # Add http if missing to ensure urlparse can handle it correctly
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Split the hostname by '.' and remove 'www' if it's the first element
    hostname_parts = urlparse(url).hostname.split('.') if urlparse(url).hostname else []
    
    # Remove 'www' if it's the first element in the list of parts
    if hostname_parts[0] == 'www':
        hostname_parts.pop(0)
    
    # Count subdomains by subtracting 2 (for the domain and TLD)
    return max(0, len(hostname_parts) - 2)

def is_https(url): return 1 if url.startswith('https://') else 0

def is_url_shortener(url):
    """Check if the given URL is a URL shortener."""  
    # Create a set of URL shorteners from the response
    shortener_domains = set(line.strip() for line in url_shortener_response.text.splitlines() if line.strip())
    
    # Ensure the URL starts with a valid scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Extract the domain
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]  # Remove "www." if present

    # Return 1 if the domain is a URL shortener, otherwise return 0
    return 1 if domain in shortener_domains else 0

def get_domain_registration_length(url): # Not using
    """Return 1 if the domain registration length is less than a year, else 0."""
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        registration_length = (w.expiration_date - w.creation_date).days if w.expiration_date and w.creation_date else 0
        return 1 if registration_length < 365 else 0
    except:
        return -1

def has_non_standard_port(url): # Not using
    """Check if the URL uses a non-standard port."""
    parsed_url = urlparse(url)
    return int(parsed_url.port not in [80, 443] if parsed_url.port else False)

def has_dns_record(url):
    """Check if the domain has a DNS record."""
    # Add 'http://' if the URL does not start with http:// or https://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to http if no scheme is provided

    try:
        domain = urlparse(url).netloc
        # Remove 'www.' if present to get the actual domain
        domain = domain.replace('www.', '')
        
        # Query for A records
        result = dns.resolver.resolve(domain, 'A')
        return int(bool(result))  # Returns 1 if there are A records, otherwise 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return 0  # No DNS record or domain does not exist
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0

def get_uppercase_ratio(url):
    """Return the ratio of uppercase letters to total characters in the URL."""
    uppercase_count = sum(1 for char in url if char.isupper())
    return uppercase_count / len(url) if len(url) > 0 else 0

def has_suspicious_keywords(url):
    """Check for common suspicious keywords in the URL path and query parameters."""
    url_parts = urlparse(url)
    # List of suspicious keywords
    suspicious_keywords = [
        'access', 'accounts', 'auth', 'security', 'portal', 'user', 'company',
        'admin', 'credential', 'identity', 'login', 'password', 'privilege',
        'token', 'validation', 'assurance', 'availability', 'confidentiality',
        'integrity', 'privacy', 'safety', 'trust', 'verification', 'check', 
        'key', 'lock', 'biometrics', 'authorize', 'authentication', 'session',
        'profile', 'service', 'support', 'notify', 'email',
        'update', 'secure', 'notification', 'transaction', 'validate', 
        'confirmation', 'manager', 'assistant', 'dashboard', 'information', 
        'communication', 'finance', 'maintenance', 'customer', 'invoice', 
        'billing', 'subscription', 'order', 'shipment', 'purchase', 
        'alert', 'billinginfo', 'receipt', 'accountinfo', 'payment', 
        'invoiceinfo', 'orderinfo', 'pay', 
        'claim', 'confirm', 'urgent', 'required', 
        'reset', 'suspend', 'verify', 'suspicious', 
        'alert', 'immediate', 'account', 'data', 'breach', 
        'click', 'follow', 'link', 'continue', 'password', 
        'win', 'congratulations', 'earn', 
        'free', 'investment', 'prize', 'money', 'offer', 
        'service', 'referral', 'download', 'install', 
        'conditions', 'membership', 'exclusive', 
        'limited', 'opportunity', 'risk'
    ]

    
    path_query = (url_parts.path + url_parts.query).lower()
    return int(any(keyword in path_query for keyword in suspicious_keywords))


def get_path_length(url):
    """Return the length of the URL path, excluding the leading slash."""
    # Check if the URL has a scheme; if not, prepend 'http://' for parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # You can choose http or https; http is generally safe for parsing

    # Use urlparse to extract the path
    path = urlparse(url).path
    
    # Exclude leading slash and return the length
    return len(path) - 1 if path.startswith('/') else len(path)

def has_numbers_in_domain(url): # Not using
    """Check if the domain contains numbers."""
    domain = urlparse(url).netloc
    return int(any(char.isdigit() for char in domain))

def get_redirections_count(url):
    """Count the number of redirections (//) in the URL."""
    # Check if '://' exists in the URL
    if '://' in url:
        # Get the part of the URL after '://'
        part_after_slash = url.split('://', 1)[1]
    else:
        part_after_slash = url

    # Count occurrences of '//'
    return part_after_slash.count('//')

def get_number_of_letters(url):
    """Count the number of letters in the URL (excluding special characters and digits)."""
    # Parse the URL to extract different components
    parsed_url = urlparse(url)
    
    # Concatenate the netloc, path, and query to consider all letters in the URL
    full_url = parsed_url.netloc + parsed_url.path + parsed_url.query
    
    # Filter out non-letter characters and count letters
    letter_count = sum(char.isalpha() for char in full_url)
    
    return letter_count

def get_ratio_of_letters(url):
    return get_number_of_letters(url)/get_url_length(url)

def get_number_of_equal(url):
    return url.count('=')

def get_number_of_question(url):
    return url.count('?')

def get_number_of_and(url):
    return url.count('&')

def get_number_of_at(url):
    return url.count('@')

def get_number_of_hashtag(url):
    return url.count('#')

def get_number_of_percent(url):
    return url.count('%')

def get_number_of_dash(url):
    return url.count('-')

def get_number_of_other_chars(url):
    # Exclude alphanumeric, common symbols, and characters covered by individual functions
    special_chars = re.sub(r'[A-Za-z0-9\/\.=?&@#%-]', '', url)
    # Remove duplicate consecutive characters (if needed)
    special_chars = re.sub(r'(.)\1+', r'\1', special_chars)
    return len(special_chars)

def get_letter_continuation(url):
    # Parse URL to remove scheme and 'www'
    parsed_url = urlparse(url)
    domain_path = parsed_url.netloc + parsed_url.path
    # Remove 'www' if it exists at the start
    domain_path = domain_path.lstrip('www.')
    
    # Find all consecutive letter sequences
    letter_sequences = re.findall(r'[A-Za-z]+', domain_path)
    # Return the length of the longest sequence, or 0 if none found
    return max(len(seq) for seq in letter_sequences) if letter_sequences else 0

def get_special_char_continuation(url):
    # Parse URL to remove scheme and ignore '://'
    parsed_url = urlparse(url)
    domain_path = parsed_url.netloc + parsed_url.path
    
    # Find all consecutive special character sequences
    special_char_sequences = re.findall(r'[^A-Za-z0-9]+', domain_path)
    # Return the length of the longest sequence, or 0 if none found
    return max(len(seq) for seq in special_char_sequences) if special_char_sequences else 0


def get_number_of_digits(url):
    """Return the number of digits in the URL."""
    return sum(char.isdigit() for char in url)

def get_ratio_of_digits(url):
    """Return the ratio of digits to the total length of the URL."""
    return get_number_of_digits(url) / get_url_length(url)

def has_valid_ssl(url):
    """Check if the URL has a valid SSL certificate."""
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
        
    # Extract the domain
    domain = urlparse(url).netloc

    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(3)
            sock.connect((domain, 443))
        return 1  # SSL certificate is valid
    except Exception as e:
        return 0  # SSL certificate is invalid or not present
    
#  __________________________________________________________________________________
# |                                                                                  |
# |                                 NEW FEATURES                                     |
# |                                                                                  |
# |__________________________________________________________________________________|

import math
import re

def get_entropy(url):
    """Calculate the entropy of a string (URL) based on character frequency and patterns."""
    # Check if the input is a string
    if not isinstance(url, str):
        raise ValueError("Input must be a string.")

    # Normalize the URL (you might want to handle www. or https://, etc.)
    url = url.lower()
    
    # Check for suspicious patterns (e.g., long sequences of random characters)
    if re.search(r'[A-Za-z0-9]{30,}', url):  # Example: long sequences of alphanumeric characters
        return 5.0  # Arbitrary high value for potentially phishing URLs

    # Create a frequency dictionary
    freq = {}
    for char in url:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    entropy = 0.0
    length = len(url)
    
    if length == 0:  # To prevent division by zero
        return 0.0

    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    # Scale the entropy value (optional)
    # You can adjust this scaling factor based on empirical observations
    scaled_entropy = entropy * (length / 100)  # Scale based on length

    return scaled_entropy

def has_file_extension(url):
    """Check if the URL contains common file extensions."""
    # List of potentially suspicious file extensions
    suspicious_extensions = [
        '.exe', '.zip', '.rar', '.js', '.bat', '.cmd', '.php', 
        '.asp', '.aspx', '.html', '.htm', '.pdf', '.jsp', '.cgi',
        '.pl', '.sh', '.sql'
    ]
    
    # Create a regex pattern to check for file extensions
    pattern = r'([A-Za-z0-9-_]+(\.(?:' + '|'.join(re.escape(ext[1:]) for ext in suspicious_extensions) + '))?)$'
    
    # Search the URL for any of the specified file extensions
    match = re.search(pattern, url)
    
    return 1 if match else 0  # Return 1 for True, 0 for False

def is_valid_tld(url):
    """Check if the URL has a valid TLD using the Public Suffix List."""
    # Process the content of the file to extract valid TLDs
    for line in valid_tlds_response.text.splitlines():
        if line.startswith('//') or not line.strip():
            continue
        valid_tlds.add(line.strip())

    # Check if the URL has a scheme; if not, prepend 'http://' for parsing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Adding https for parsing purposes

    hostname = urlparse(url).hostname  # Extract hostname using urlparse
    if hostname:
        hostname_parts = hostname.split('.')

        # Start from the end and check for longest valid TLD
        for i in range(len(hostname_parts)):
            tld_candidate = '.'.join(hostname_parts[i:])
            if tld_candidate in valid_tlds:
                return 1  # Valid TLD found
    return 0  # No valid TLD found

def get_tld_length(url): # UPDATE THIS FUNCTION
    """Get the length of the TLD from a URL, considering multiple TLD parts."""
    # Process the content of the file to extract valid TLDs
    for line in valid_tlds_response.text.splitlines():
        if line.startswith('//') or not line.strip():
            continue
        valid_tlds.add(line.strip())

    # Check if the URL has a scheme; if not, prepend 'http://' for parsing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Adding https for parsing purposes

    hostname = urlparse(url).hostname  # Extract hostname using urlparse
    if hostname:
        hostname_parts = hostname.split('.')
        
        # Start checking from the end for valid TLDs
        for i in range(len(hostname_parts)):
            tld_candidate = '.'.join(hostname_parts[i:])
            if tld_candidate in valid_tlds:
                return len(tld_candidate.split('.'))  # Return number of parts in the TLD
    return 0  # Return 0 if hostname is None or no valid TLD found

def is_similar_to_legit_domain(url):
    """Check for similarity to known legitimate domains using a dataset of top domains."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Choose http or https for parsing
    # Extract hostname from the URL
    hostname = urlparse(url).hostname
    if not hostname:
        return 0  # Return 0 if no hostname is found

    domain = urlparse(url).hostname
    if domain.startswith("www."):
        domain = domain[4:]

    if domain in page_ranking_df.index:
        return 0

    # Function to perform the similarity check
    def check_similarity():
        nonlocal result  # Allow access to the result variable from the outer scope
        for legit_domain in page_ranking_df.index[:1000]:  # Limit to top 1000 for faster checks
            similarity = SequenceMatcher(None, hostname, legit_domain).ratio()
            if similarity > 0.65:  # Adjust the threshold based on your needs
                result = 1  # Similar to a legitimate domain
                return
        result = 0  # Not similar to any legitimate domain

    result = 0  # Default result
    thread = Thread(target=check_similarity)
    thread.start()
    thread.join(timeout=0.65)  # Wait for the thread to finish with a timeout of 0.65 seconds

    if thread.is_alive():  # If the thread is still running after the timeout
        return 0  # Return 0 if it took too long

    return result

def get_domain_age(url):
    """Get the age of the domain in days."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Choose http or https for parsing

    hostname = urlparse(url).hostname 
    if hostname:
        try:
            domain_info = whois.whois(hostname)
            creation_date = domain_info.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]  # Sometimes it's a list

            age = (datetime.now() - creation_date).days if creation_date else 0
            return age
        except Exception as e:
            return 0  # Return 0 if there's an error
    return 0

def is_suspicious_tld(url):
    """Check if the TLD of the given URL matches any suspicious TLD."""
    parsed_url = urlparse(url)
    tld = parsed_url.hostname.split('.')[-1].lower() if parsed_url.hostname else ''
    
    # Check if the TLD is in the suspicious TLDs set
    return 1 if tld in suspicious_tlds else 0

def has_mx_record(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Choose http or https for parsing

    domain = urlparse(url).hostname
    if domain.startswith("www."):
        domain = domain[4:]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return 1 if len(mx_records) > 0 else 0
    except:
        return 0
    
def has_unicode_characters(url):
    """Check if the URL contains Unicode characters."""
    return 1 if any(ord(char) > 127 for char in url) else 0

# extract all links in content
def extract_links(email_content):
   
   # Regex to capture links
    regex = r"(?<![@\w:])(?:https?:\/\/|ftp:\/\/|www\.)[a-zA-Z0-9.-]+(?:[\/a-zA-Z0-9.-]*)[^\s<>,\'\"\)]*\b\/?=?|(?<![@\w:])[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:[\/a-zA-Z0-9.-]*)[^\s<>,\'\"\)]*\b\/?=?|(?:\d{1,3}\.){3}\d{1,3}(?:[\/a-zA-Z0-9.-]*)[^\s<>,\'\"\)]*\b\/?=?|http:\/\/\[[0-9a-fA-F:]+\](?:[\/a-zA-Z0-9.-]*)[^\s<>,\'\"\)]*\b\/?=?|ftp:[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|http:\/\/\[[0-9a-fA-F:]+\](?:\:[0-9]+)?[\/a-zA-Z0-9.-]*\/?"
    
    # Regex to capture email addresses
    email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    # Find all matches using the regex
    links = re.findall(regex, email_content)
    emails = re.findall(email_regex, email_content)

    # Remove any email address from the list of links captured 
    cleaned_links = [item for item in links if item not in emails]

    # Remove duplicates
    unique_links = list(set(cleaned_links))
    return unique_links

# def extract_features(url):
#     return {
#         'get_url_length': get_url_length(url),
#         'get_tld_length': get_tld_length(url),
#         'get_domain_length': get_domain_length(url),
#         'get_path_length': get_path_length(url),
#         'get_open_page_rank': get_open_page_rank(url),
#         'get_redirections_count': get_redirections_count(url),
#         'get_char_continuation_rate': get_char_continuation_rate(url), # Not using 
#         'get_num_subdomains': get_num_subdomains(url),
#         # 'get_domain_registration_length': get_domain_registration_length(url), # Doesn't seem to work (always returns -1)
#         'get_uppercase_ratio': get_uppercase_ratio(url),
#         'get_number_of_letters': get_number_of_letters(url),
#         'get_ratio_of_letters': get_ratio_of_letters(url),
#         'get_number_of_equal': get_number_of_equal(url),
#         'get_number_of_question': get_number_of_question(url),
#         'get_number_of_and': get_number_of_and(url),
#         'get_number_of_at': get_number_of_at(url),
#         'get_number_of_hashtag': get_number_of_hashtag(url),
#         'get_number_of_percent': get_number_of_percent(url),
#         'get_number_of_dash': get_number_of_dash(url),
#         'get_number_of_other_chars': get_number_of_other_chars(url),
#         'get_letter_continuation': get_letter_continuation(url),
#         'get_special_char_continuation': get_special_char_continuation(url),
#         'get_number_of_digits': get_number_of_digits(url),
#         'get_ratio_of_digits': get_ratio_of_digits(url),
#         'get_entropy': get_entropy(url),
#         'get_tld_length': get_tld_length(url),
#         'get_domain_age': get_domain_age(url),

#         'is_domain_ip': is_domain_ip(url),
#         'is_https': is_https(url),
#         'is_url_shortener': is_url_shortener(url),
#         'is_valid_tld': is_valid_tld(url),
#         'is_similar_to_legit_domain': is_similar_to_legit_domain(url),
#         'is_suspicious_tld': is_suspicious_tld(url),

#         # 'has_non_standard_port': has_non_standard_port(url), # Doesn't seem to work (always returns 0)
#         'has_dns_record': has_dns_record(url),
#         'has_suspicious_keywords': has_suspicious_keywords(url),
#         'has_valid_ssl': has_valid_ssl(url),
#         'has_file_extension': has_file_extension(url),
#         'has_mx_record': has_mx_record(url),
#         'has_unicode_characters': has_unicode_characters(url),
#     }


def extract_features(url):
    return {
        'URLLength': get_url_length(url),
        'TLDLength': get_tld_length(url),
        'DomainLength': get_domain_length(url),
        'PathLength': get_path_length(url),
        'PageRank': get_open_page_rank(url),
        'RedirectionsCount': get_redirections_count(url),
        'NumSubdomains': get_num_subdomains(url),
        'UppercaseRatio': get_uppercase_ratio(url),
        'NumLetters': get_number_of_letters(url),
        'RatioLetters': get_ratio_of_letters(url),
        'NumEqual': get_number_of_equal(url),
        'NumQuestion': get_number_of_question(url),
        'NumAnd': get_number_of_and(url),
        'NumAt': get_number_of_at(url),
        'NumHashtag': get_number_of_hashtag(url),
        'NumPercent': get_number_of_percent(url),
        'NumDash': get_number_of_dash(url),
        'NumOtherChars': get_number_of_other_chars(url),
        'LetterContinuation': get_letter_continuation(url),
        'SpecialCharsContinuation': get_special_char_continuation(url),
        'NumDigits': get_number_of_digits(url),
        'RatioDigits': get_ratio_of_digits(url),
        'IsIP': is_domain_ip(url),
        'IsHTTPS': is_https(url),
        'IsURLShort': is_url_shortener(url),
        'HasDNS': has_dns_record(url),
        'HasSuspicious': has_suspicious_keywords(url),
        'HasValidSSL': has_valid_ssl(url),
        'Entropy': get_entropy(url),
        'HasFileExtension': has_file_extension(url),
        'IsValidTLD': is_valid_tld(url),
        'SimilarToLegitDomain': is_similar_to_legit_domain(url),
        'DomainAge': get_domain_age(url),
        'IsSuspiciousTLD': is_suspicious_tld(url),
        'HasMXRecord': has_mx_record(url),
        'HasUnicodeChars': has_unicode_characters(url)
    }


# email_content = "Here are some links: https://example.com, www.testsite.org/page, and an IP link http://192.168.1.1/path."
# # email_content_none = "Here are some links: none"
# found_links = extract_links(email_content)
# # found_links = extract_links(email_content_none)
# print(found_links)
# for link in found_links:
#     print(extract_features(link))
