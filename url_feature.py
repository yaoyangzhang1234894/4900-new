import re
import os
from urllib.parse import urlparse
import urllib.parse
import tldextract

def url_length(url): #check
    return len(url) 



def get_hostname(url):  #check
    parsed_url = urlparse(url)
    return len(parsed_url.hostname)

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0
    

def nb_dots(url):  #check
    return url.count('.') 

def nb_hyphens(url): #check
    return url.count('-')

def nb_at(url):
    return url.count('@')

def nb_qm(url):
    return url.count('?')

def nb_and(url):
    return url.count('&')

def nb_or(url):
    return url.count('|')

def nb_eq(url):    #check
    return url.count('=')

def nb_underscore(url):
    return url.count('_')

def nb_tilde(url):
    return url.count('~')

def nb_percent(url):
    return url.count('%')

def nb_slash(url):   #check
    return url.count('/')

def nb_star(url):
    return url.count('*')

def nb_colon(url):
    return url.count(':')

def nb_comma(url):
    return url.count(',')

def nb_semicolon(url):
    return url.count(';')

def nb_dollar(url):
    return url.count('$')

def nb_space(url):
    return url.count(' ')

def nb_www(url):   #check
    return url.count('www')

def nb_com(url):
    return url.count('.com')

def nb_dslash(url):
    return url.count('//')

def http_in_path(url):
    # Checks if "http" appears in the path part of the URL
    parsed_url = urlparse(url)
    return 'http' in parsed_url.path

def https_token(url):
    # Checks if the URL uses HTTPS
    return url.startswith('https')

def ratio_digits_url(url):
    # Calculates the ratio of digits to the total length in the URL
    digits = sum(c.isdigit() for c in url)
    return digits / len(url) if len(url) > 0 else 0

def ratio_digits_host(url):
    # Calculates the ratio of digits to the total length in the hostname
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ''
    digits = sum(c.isdigit() for c in hostname)
    return digits / len(hostname) if len(hostname) > 0 else 0

def punycode(url):
    # Checks if the hostname is in punycode format
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ''
    return hostname.startswith('xn--')

def port(url):
    # Extracts the port number if specified, otherwise returns None
    parsed_url = urlparse(url)
    return parsed_url.port

def tld_in_path(url):
    # Checks if a top-level domain (like .com, .org) appears in the path
    parsed_url = urlparse(url)
    path = parsed_url.path
    # Common TLDs (you may expand this list as needed)
    tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co', '.us', '.uk']
    return any(tld in path for tld in tlds)

def tld_in_subdomain(url):
    # Checks if a TLD is present in the subdomain part of the URL
    parsed_url = urlparse(url)
    subdomain = parsed_url.hostname.split('.')[0] if parsed_url.hostname else ''
    tlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'us', 'uk']
    return any(tld in subdomain for tld in tlds)

def abnormal_subdomain(url):
    # Checks for 'abnormal' subdomains, like subdomains with unusual length or patterns
    parsed_url = urlparse(url)
    hostname_parts = parsed_url.hostname.split('.') if parsed_url.hostname else []
    return len(hostname_parts) > 2

def nb_subdomains(url):
    # Counts the number of subdomains in the URL
    parsed_url = urlparse(url)
    hostname_parts = parsed_url.hostname.split('.') if parsed_url.hostname else []
    return max(0, len(hostname_parts) - 2)

def prefix_suffix(url):
    # Checks if there is a dash '-' in the domain, often a sign of phishing
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ''
    return '-' in hostname


def extract_words_from_url(url):
    #idea from https://github.com/manthan2305/webpage-phishing-detection/blob/main/scripts/feature_extractor.py#L933
    # Parse the URL into its components
    parsed_url = urlparse(url)
    
    # Split hostname into domain and subdomain parts
    hostname_parts = parsed_url.hostname.split('.') if parsed_url.hostname else []
    if len(hostname_parts) > 1:
        # Last part is the TLD, second-to-last is the domain
        domain = hostname_parts[-2]
    else:
        domain = hostname_parts[0] if hostname_parts else ''
    
    subdomain = '.'.join(hostname_parts[:-2]) if len(hostname_parts) > 2 else ''
    # print(hostname_parts,domain,subdomain)
    # Extract the path part
    path = parsed_url.path
    # extracted_domain = tldextract.extract(url)
    # subdomain = extracted_domain.subdomain
    # tmp = url[url.find(extracted_domain.suffix):len(url)]
    # pth = tmp.partition("/")
    # path = pth[1] + pth[2]
    
    # Split domain, subdomain, and path into words based on delimiters
    
    w_domain = re.split(r"[\-|\.|\/|\?|\=|\@|\&|\%|\:|\_]", domain.lower())
    w_subdomain = re.split(r"[\-|\.|\/|\?|\=|\@|\&|\%|\:|\_]", subdomain.lower())
    w_path = re.split(r"[\-|\.|\/|\?|\=|\@|\&|\%|\:|\_]", path.lower())
        
    # Filter out any empty strings
    w_domain = list(filter(None, w_domain))
    w_subdomain = list(filter(None, w_subdomain))
    w_path = list(filter(None, w_path))
    # print(w_domain,w_subdomain,w_path)
    # Return the words in each part as separate lists
    return w_domain, w_subdomain, w_path

    
def get_domain(url):
    o = urllib.parse.urlsplit(url)
    return o.hostname, tldextract.extract(url).domain, o.path

def length_words_raw(url):
    # Use extract_words_from_url to get the lists of words in the URL
    w_domain, w_subdomain, w_path = extract_words_from_url(url)
    
    # Combine all words and calculate the total length
    total_length = len(w_domain + w_subdomain + w_path)
    return total_length

def shortest_word_host(url):
    # Use extract_words_from_url to get words in the domain and subdomain
    w_domain, w_subdomain, _ = extract_words_from_url(url)
    
    # Combine words from domain and subdomain to form the host words list
    w_host = w_domain + w_subdomain
    
    # Find and return the shortest word in the host
    return len(min(w_host, key=len)) if w_host else 0

def shortest_word_path(url):
    _,_,w_path = extract_words_from_url(url)
    
    return len(min(w_path, key=len)) if w_path else 0

def longest_word_raw(url):
    w_domain, w_subdomain, w_path = extract_words_from_url(url)
    total = w_domain+w_subdomain+w_path
    return len(max(total, key=len)) if w_path else 0

def longest_word_host(url):
    w_domain, w_subdomain, w_path = extract_words_from_url(url)
    total = w_domain+w_subdomain
    return len(max(total, key=len)) if w_path else 0

def longest_word_path(url):
    w_domain, w_subdomain, w_path = extract_words_from_url(url)
    
    return len(max(w_path, key=len)) if w_path else 0


def avg_word_raw(url):
    w_domain, w_subdomain, w_path = extract_words_from_url(url)
    
    # Combine all words from domain, subdomain, and path
    all_words = w_domain + w_subdomain + w_path
    
    # Calculate the average word length
    total_length = sum(len(word) for word in all_words)
    average_length = total_length / len(all_words) if all_words else 0
    
    return average_length


def avg_word_host(url):
    w_domain, w_subdomain, w_path = extract_words_from_url(url)
    
    # Combine all words from domain, subdomain, and path
    all_words = w_domain + w_subdomain
    
    # Calculate the average word length
    total_length = sum(len(word) for word in all_words)
    average_length = total_length / len(all_words) if all_words else 0
    
    return average_length


def avg_word_path(url):
    w_domain, w_subdomain, w_path = extract_words_from_url(url)
    
    # Combine all words from domain, subdomain, and path
    all_words = w_path
    
    # Calculate the average word length
    total_length = sum(len(word) for word in all_words)
    average_length = total_length / len(all_words) if all_words else 0
    
    return average_length

url = "http://www.crestonwood.com/router.php"
url2 = "http://vamoaestudiarmedicina.blogspot.com/"
url3 = "http://www.mutuo.it"
# print(length_words_raw(url2),shortest_word_host(url2),shortest_word_path(url2))

url_checks = [("length_url", url_length),
              ("length_hostname", get_hostname),
    ("nb_dots",nb_dots),
    ("nb_hyphens",nb_hyphens),
    ("nb_eq",nb_eq),
    ("nb_slash",nb_slash),
    ("nb_www",nb_www),
    ("length_words_raw",length_words_raw),
    ("shortest_word_host", shortest_word_host),
    ("shortest_word_path", shortest_word_path),
    ("longest_words_raw", longest_word_raw),
    ("longest_word_host", longest_word_host),
    ("longest_word_path", longest_word_path),
    ("avg_words_raw", avg_word_raw),
    ("avg_word_host", avg_word_host),
    ("avg_word_path", avg_word_path)
]
def run_url_checks(url):
    results = {}
    for check_name, check_func in url_checks:
        results[check_name] = check_func(url)
    return results
results = run_url_checks(url)
for check_name, result in results.items():
    print(f"{check_name}: {result}")