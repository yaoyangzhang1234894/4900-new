import pandas as pd
import requests
import re
import json
from urllib.parse import urlparse
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import normalize
from scipy.sparse import csr_matrix

######################################################################
# CODE FOR CHECK IF LINK IS IN DATABASE
######################################################################

page_ranking_df = pd.read_csv("https://github.com/spongeb0bzzz/CSI-4900/raw/main/data/top10milliondomains.csv")
page_ranking_df.columns = page_ranking_df.columns.str.strip()  # Clean column names
page_ranking_df.set_index('Domain', inplace=True)  # Set index to 'Domain'

def clean_link(link):
    # Validate if link is in a correct URL format
    try:
        if not link.startswith(('http://', 'https://')):
            link = 'http://' + link  # Prepend a scheme if missing
        parsed_url = urlparse(link)
        netloc = parsed_url.netloc
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        return netloc
    except Exception as e:
        print(f"Skipping invalid link: {link} - Error: {e}")
        return None

# Function to download and parse the phishing links
def load_and_process_sources():
    # Load the first dataset (combined phishing and benign URLs)
    combined_urls_url = "https://raw.githubusercontent.com/spongeb0bzzz/CSI-4900/refs/heads/main/data/combined_urls.csv"
    combined_urls = pd.read_csv(combined_urls_url)

    # Drop rows with null values in 'link'
    combined_urls.dropna(subset=['link'], inplace=True)

    # Create a set of full links with their status (0 for benign, 1 for phishing)
    combined_urls_set = set(zip(combined_urls['link'], combined_urls['status']))

    # Load the second set of sources (multiple files from GitHub)
    sources = [
        "https://raw.githubusercontent.com/phishfort/phishfort-lists/refs/heads/master/blacklists/domains.json",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/refs/heads/master/phishing-links-ACTIVE.txt",
        "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/full-domains-aa.txt",
        "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/full-domains-aa.txt.txt",
        "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/full-domains-ab.txt",
        "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/full-domains-ab.txt.txt"
    ]

    # Process each source
    for source_url in sources:
        response = requests.get(source_url)
        
        # For JSON files, parse and add each domain as a phishing link
        if source_url.endswith('.json'):
            domains = json.loads(response.text)
            for domain in domains:
                combined_urls_set.add((domain, 1))  # Mark all entries as phishing

        # For text files, add each line as a phishing link
        else:
            for line in response.text.splitlines():
                if line:  # Avoid empty lines
                    combined_urls_set.add((line, 1))  # Mark all entries as phishing

    return pd.DataFrame(list(combined_urls_set), columns=['link', 'status'])

def clean_dataset(dataset):
    regex = r"(?:https?:\/\/[a-zA-Z0-9.-]+|ftp:\/\/[a-zA-Z0-9.-]+|\/\/[a-zA-Z0-9.-]+|www\.[a-zA-Z0-9.-]+|[a-zA-Z0-9-]+\.[a-zA-Z]{1,}|(?:\d{1,3}\.){3}\d{1,3})(?:[\/a-zA-Z0-9.-]*)[^\s<>,\'\"\)]*"

    # Apply the regex to the 'link' column to capture valid URLs
    valid_links = dataset['link'].str.contains(regex, regex=True)

    # Count the number of valid links
    num_valid_links = valid_links.sum()
    total_links = dataset.shape[0]

    # Calculate the percentage of captured links
    percent_captured = (num_valid_links / total_links) * 100 if total_links > 0 else 0

    # Print the results
    # print(f"Number of valid links: {num_valid_links}")
    # print(f"Total links: {total_links}")
    # print(f"Percentage of captured links: {percent_captured:.2f}%")

    # Filter the dataset to get links that weren't captured by the regex
    uncaptured_links = dataset[~valid_links]

    # Set pandas to display all rows
    pd.set_option('display.max_rows', None)

    # Print the entire DataFrame of uncaptured links
    # print("Links not captured by the regex:")
    # print(uncaptured_links)

    # Keep only the captured links
    dataset = dataset[valid_links]

    # Mapping string values to integers in the 'status' column
    dataset['status'] = dataset['status'].replace({
        '1': 1,
        '0': 0,
        'malware': 1
    })

    # Check if links are in the page ranking dataset and remove them if they are
    page_ranking_set = set(page_ranking_df.index)
    dataset = dataset[~dataset['link'].isin(page_ranking_set)]

    # Optionally, reset the index if desired
    dataset.reset_index(drop=True, inplace=True)

    return dataset

combined_df = load_and_process_sources()
combined_df = clean_dataset(combined_df)
combined_df.set_index('link', inplace=True)  # Set index to 'link'

def get_result_from_database(link):
    '''
    Returns 1 (100%) if the link is phishing
    Returns 0 (0%) if the link is benign
    Returns None if the link is not found
    Return -1 if the domain 
    '''
    cleaned_link = clean_link(link)

    if link in combined_df.index:
        return combined_df.loc[link, 'status']  # Return the status (0 for benign, 1 for phishing)

    # Check if the link exists in the combined_df (phishing dataset)
    if cleaned_link in combined_df.index:
        if cleaned_link == link:
          return combined_df.loc[cleaned_link, 'status']  # Return the status (0 for benign, 1 for phishing)
        return 0.75 if combined_df.loc[cleaned_link, 'status'] == 1 else 0.25 # Return the status if the link partially matches a link in the dataset (-2 if likely benign, -1 if likely phishing)

    # Check if the link exists in the page_ranking_df (benign domains)
    if cleaned_link in page_ranking_df.index:
        if cleaned_link == link: 
          return 0  # Return 0 for benign if the domain is found in the page ranking dataset
        return 0.25  # Return -2 if the link partially matches a domain in the dataset


    return None  # If the link is not found in either dataset, return None


######################################################################
# CODE FOR CHECKING IP ADDRESS
######################################################################

def extract_ips_from_url(url):
    response = requests.get(url)
    # Split the content into lines and filter out any non-IP lines
    ip_addresses = {line.strip() for line in response.text.splitlines() if re.match(r'^\d+\.\d+\.\d+\.\d+$', line.strip())}
    return ip_addresses

def combine_ip_lists():
  urls = [
    "https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/ip-list.txt",
    "https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/refs/heads/main/blacklist_ips_for_fortinet_firewall_aa.txt",
    "https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/refs/heads/main/blacklist_ips_for_fortinet_firewall_ab.txt",
    "https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/refs/heads/main/botnets_zombies_scanner_spam_ips.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/full-outgoing-ip-40k.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/full-outgoing-ip-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/full-outgoing-ip-ab.txt"
  ]

  # Combine all the malicious IP addresses into a single set
  malicious_ips = set()

  for url in urls:
      malicious_ips.update(extract_ips_from_url(url))

  return malicious_ips

malicious_ips = combine_ip_lists()

def check_sender_ip(sender_ip):
    # Check if the sender's IP is in the malicious IPs set
    if sender_ip in malicious_ips:
        return 1  # Malicious IP
    else:
        return 0  # Benign IP

######################################################################
# CODE FOR CASE-BASED REASONNING
######################################################################

vectorizer = joblib.load(r"model\cbr\CBR_vectorizer.joblib")
link_vectors = joblib.load(r"model\cbr\link_vectors.joblib")
statuses = joblib.load(r"model\cbr\statuses.joblib")
links = joblib.load(r"model\cbr\links.joblib")


def query_link_similarity(query_link, top_k=1):
    # Vectorize and normalize the query link
    query_vector = vectorizer.transform([query_link])
    query_vector = normalize(query_vector, norm='l2', axis=1)
    
    # Calculate cosine similarity via matrix multiplication
    cosine_similarities = query_vector.dot(link_vectors.T).toarray().flatten()
    
    # Get the indices of the top_k highest similarity scores
    top_indices = np.argpartition(-cosine_similarities, range(top_k))[:top_k]
    top_indices = top_indices[np.argsort(-cosine_similarities[top_indices])]

    # Collect the top-k results
    results = []
    for idx in top_indices:
        similarity_score = cosine_similarities[idx] # return similarity score from 0 to 1
        matched_link = links[idx]
        status = 1 if statuses[idx] == 1 else 0 # Return 1 if phishing or 0 if benign
        
        results.append({
            "similarity_score": similarity_score,
            "matched_link": matched_link,
            "status": status
        })
    
    return results




def get_average_similarity(link):
    output =  query_link_similarity(link, top_k= 3)


    weighted_scores = []

    for result in output:
            similarity_score = result["similarity_score"]
            status = result["status"]
            
            if status == 1:
                # Phishing: use similarity score directly
                weighted_score = similarity_score * status
            else:
                # Benign: adjust score to reflect similarity to safe links
                weighted_score = 1 - (similarity_score * (1 - status))
            
            weighted_scores.append(weighted_score)

    return sum(weighted_scores) /3 

'''
Example query:
query = "https://storage.googleapis.com/hasssalee/hamsrefly.html#?Z289MSZzMT0xOTk2Mjg5JnMyPTQyOTcxODMyMSZzMz1DQQ=="
results = query_link_similarity(query, top_k=3)

# Display the most similar links with similarity score and status
for result in results:
    score = float(result["similarity_score"])  # Explicitly cast to float if necessary
    matched_link = result["matched_link"]
    status = result["status"]
    
    print(f"Similarity Score: {score:.2f}%")
    print(f"Matched Link: {matched_link}")
    print(f"Status: {status}\n")
'''


# test = "http://e2qx0eun4dbzfe8d.sslsecure.eu.com/4yZfFs6128cfzp243vcbaeqcsqa983YFBYAGTVGRXYCDU74803/6487X9?WW3Z3PF2ZT7PIXXSGPNTRMQ100GL="

# result = query_link_similarity(test, top_k= 3)

# for item in result:
#     print(f"Similarity Score: {item['similarity_score'] * 100:.2f}%")
# # # result = get_average_similarity(test)

# print(result)

# result2 = get_result_from_database(test)

# print(f'result = {result2}')
# print(type(result2))


