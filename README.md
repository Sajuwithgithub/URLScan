# URLScan
Virustotal URL Lookup from a file
This program allows you to send files to VirusTotal for analysis quickly. Integrating with the VirusTotal API allows you to conveniently submit files and receive analysis results directly from your computer.

**Prerequisties**
1. Python3
2. Libraries from requirements.txt.
3. API key from VirusTotal. (You can obtain an API key by creating an account on the VirusTotal website. See the image below.)

**Setup**
1. Clone the repository to your local machine or download the source code.
git clone https://github.com/Sajuwithgithub/URLScan

2. Navigate to the appropriate directory by executing the following command:
cd URLScan

3. Install the required dependencies by running the following command:
pip3 install -r requirements.txt

Open the "virustotal_url_scan.py" file in a text editor and replace the api_key variable with your own VirusTotal API key under the value attribute "apikey".

**Usage**

1. Program will read each entry from a file . Please note the first entry in the file should be "URL"
For Eg - If the file name is URLCheck.csv then the first column in the spreadsheet should have the column name as "URL".
2. Post execution of the URLscan.py the output file is generated under the name folder structure with folder name as 'VTop.csv"

   
