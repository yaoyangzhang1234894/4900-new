import re
import os
from urllib.parse import urlparse
import urllib.parse
import tldextract



def URLLength(url): #改过
    return len(url)-1

#2
def DomainLength(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname or url
    return len(domain)

#3
def IsDomainIP(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname or url
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))

#4
def TLDLength(url):
    parsed_url = urlparse(url)
    hostname_parts = parsed_url.hostname.split('.') if parsed_url.hostname else []
    tld = hostname_parts[-1] if len(hostname_parts) > 1 else ''
    return len(tld)

#5
def NoOfSubDomain(url):
    parsed_url = urlparse(url)
    hostname_parts = parsed_url.hostname.split('.') if parsed_url.hostname else []
    return max(0, len(hostname_parts) - 2)

# 6. Has Obfuscation (using `@` to hide true domain)
def HasObfuscation(url):
    return '@' in url

# 7. Number of Obfuscated Characters (like `@`)
def NoOfObfuscatedChar(url):
    return url.count('@')

# 8. Obfuscation Ratio
def ObfuscationRatio(url):
    obfuscated_count = url.count('@')
    return obfuscated_count / len(url) if len(url) > 0 else 0

#9
def NoOfLettersInURL(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else url
    
    # Remove common subdomains like 'www'
    hostname = hostname.replace("www.", "")
    
    # Count only alphabetic characters
    return sum(1 for char in hostname if char.isalpha())
#10
def LetterRatioInURL(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else url
    
    # Remove common subdomains like 'www'
    hostname = hostname.replace("www.", "")
    
    # Count only alphabetic characters
    letter_count =sum(1 for char in hostname if char.isalpha())
    return letter_count / len(url) if len(url) > 0 else 0

# 11. Number of Digits
def NoOfDegitsInURL(url):
    return sum(1 for char in url if char.isdigit())

# 12. Digit Ratio
def DegitRatioInURL(url):
    digit_count = sum(1 for char in url if char.isdigit())
    return digit_count / len(url) if len(url) > 0 else 0

# 13. Number of Equals
def NoOfEqualsInURL(url):
    return url.count('=')

# 14. Number of Question Marks
def NoOfQMarkInURL(url):
    return url.count('?')

# 15. Number of Ampersands
def NoOfAmpersandInURL(url):
    return url.count('&')


# 16. Number of Other Special Characters in URL
def NoOfOtherSpecialCharsInURL(url):
    # Exclude alphanumeric and commonly used symbols like '?' '&' '=' '@'
    special_chars = re.sub(r'[A-Za-z0-9\/\.]', '', url)
    special_chars = re.sub(r'(.)\1+', r'\1', special_chars)
    return len(special_chars)

# 17. Special Character Ratio in URL
def SpacialCharRatioInURL(url):
    return NoOfOtherSpecialCharsInURL(url) / URLLength(url) if URLLength(url) > 0 else 0

# 18. Is HTTPS
def IsHTTPS(url):
    return url.startswith('https')

# 19. Number of URL Redirects
def NoOfURLRedirect(url):
    return url.count('//') - 1

# 20. Char Countinuation RAte
def CharContinuationRate(url):
    # Find all sequences of alphabets, digits, and special characters
    alpha_sequences = re.findall(r'[A-Za-z]+', url)
    digit_sequences = re.findall(r'[0-9]+', url)
    special_sequences = re.findall(r'[^A-Za-z0-9]+', url)
    # print(alpha_sequences)
    # print(digit_sequences)
    # print(special_sequences)
    # Find the longest sequence in each category
    longest_alpha = max(len(seq) for seq in alpha_sequences) if alpha_sequences else 0
    longest_digit = max(len(seq) for seq in digit_sequences) if digit_sequences else 0
    longest_special = max(len(seq) for seq in special_sequences) if special_sequences else 0
    
    # Sum the lengths of the longest sequences
    total_length_longest_sequences = longest_alpha + longest_digit + longest_special
    # print(total_length_longest_sequences)
    # Calculate the CharContinuationRate
    url_length = len(url)
    char_continuation_rate = total_length_longest_sequences / url_length if url_length > 0 else 0
    
    return char_continuation_rate


url ="https://www.good-package.com"

def get_url_features(url):
    features = {
        "URLLength": URLLength(url),
        "DomainLength": DomainLength(url),
        "IsDomainIP": IsDomainIP(url),
        "TLDLength": TLDLength(url),
        "NoOfSubDomain": NoOfSubDomain(url),
        # "HasObfuscation": HasObfuscation(url),
        # "NoOfObfuscatedChar": NoOfObfuscatedChar(url),
        # "ObfuscationRatio": ObfuscationRatio(url),
        # "NoOfLettersInURL": NoOfLettersInURL(url),
        # "LetterRatioInURL": LetterRatioInURL(url),
        "NoOfDigitsInURL": NoOfDegitsInURL(url),
        "DigitRatioInURL": DegitRatioInURL(url),
        "NoOfEqualsInURL": NoOfEqualsInURL(url),
        "NoOfQMarkInURL": NoOfQMarkInURL(url),
        "NoOfAmpersandInURL": NoOfAmpersandInURL(url),
        # "NoOfOtherSpecialCharsInURL": NoOfOtherSpecialCharsInURL(url),
        # "SpecialCharRatioInURL": SpacialCharRatioInURL(url),
        "IsHTTPS": IsHTTPS(url),
        # "NoOfURLRedirect": NoOfURLRedirect(url)，
        "CharContinuationRate": CharContinuationRate(url)
    }
    return features

# Print features
# for feature_name, value in features.items():
#     print(f"{feature_name}: {value}")
print(get_url_features(url))