import csv
import json
import requests
import time
import base64

# //////////////////////////////////////////////
#
# Python script for VirusTotal API v3 list of IP address analysis
# by Saju Thomas.
#  Reports for each IP entry is saved to a CSV file
#
# //////////////////////////////////////////////

global apikey

apikey = 'YOUR API Key'  # Your VirusTotal API Key

# Function to check if an URL is malicious
def check_URL(domain):
    target_url = domain
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    print(url_id)
    url = "https://www.virustotal.com/api/v3/urls/" + url_id
    headers = {'x-apikey': apikey}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise requests.exceptions.RequestException(f"API request failed with status code {response.status_code}")
    response_json = response.json()
    if 'data' not in response_json:
        raise ValueError("Invalid response structure")
    attributes = response_json['data']['attributes']
    
    # JSON response parameters
    as_owner = attributes.get('as_owner')
    registrar = attributes.get('registrar')
    country = attributes.get('country')
    stat_analysis = attributes.get('last_analysis_stats')
    
    malicious = stat_analysis.get('malicious')
    suspicious = stat_analysis.get('suspicious')
    undetected = stat_analysis.get('undetected')
    harmless = stat_analysis.get('harmless')
    
    total = int(malicious) + int(suspicious) + int(undetected) + int(harmless)

    return {
        'url': domain,
        'Registrar': registrar,
        'Malicious': malicious,
        'Suspicious': suspicious,
        'Undetected': undetected,
        'Total': total
    }

# Read the CSV file
input_file = 'C:\\Users\\{Path File}\\Downloads\\URLcheck.csv'  # Input CSV file path
output_file = 'C:\\Users\\{Path File}\\Downloads\\VTop.csv'  # Output CSV file path

try:
    with open(input_file, 'r', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        ip_list = list(reader)

    if len(ip_list) > 500:
        print("IP count exceeding VirusTotal rate limit. Checking malicious score for the first 500 IPs.")
        ip_list = ip_list[:500]

    with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        fieldnames = ['url', 'Registrar', 'Malicious', 'Suspicious', 'Undetected', 'Total']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)

        writer.writeheader()
        for col in ip_list:
            try:
                column_name = 'URL'  # Column name containing IP Addresses
                url = col[column_name]
                print("Started VirusTotal URL Scan...")
                data = check_URL(url.strip())
                writer.writerow(data)
                time.sleep(15)  # Sleep to ensure we don't exceed 4 requests per minute
                
            except KeyError:
                print(f"The CSV does not contain {column_name} header.")
                break
            except requests.exceptions.RequestException as e:
                print(f"An error occurred while checking IP {url}: {e}")
                print("API rate limit per day might be completed.")
                #break
            except Exception as e:
                print(f"An unexpected error occurred while processing IP {url}: {e}")
                break
    print("IP scan completed!!")

except FileNotFoundError:
    print("The specified file was not found.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
