# NetworkScanner


# Objective
 Build a custom network scanner capable of:<br/>
- Enumerating open ports and services
- Identifying software versions and CPEs
- Mapping CPEs to known vulnerabilities
- Pulling CVE details from the NVD API
- Providing remediation steps for common ports
- Exporting all findings into a professional PDF report<br/><br/>

 # Skills Leanred
- Python scripting and debugging
- Nmap automation using Python libraries
- Working with JSON and API responses
- CPE (Common Platform Enumeration) parsing and normalization
- CVE lookup and vulnerability correlation
- PDF report generation
- Practical vulnerability assessment workflow<br/><br/>
  

# Tools Used
- Python
- Nmap (via Python library)
- Requests (API calls)
- FPDF (PDF generation)
- Visual Studio Code
- Microsoft Copilot (for iterative refinement)

# Steps

## Step 1. Library Imports

- nmap → to perform aggressive scans and extract service/version data
- requests → to query the NVD API for vulnerabilities
- FPDF → to generate a clean, readable PDF report<br/>

These three components form the core of the scanning → analysis → reporting workflow.

<img width="347" height="113" alt="image" src="https://github.com/user-attachments/assets/38fe6f12-9d84-4c6b-8d29-85d59d398f4e" /> <br/><br/>

## Step 2. Scan Function

The scanner:
- Creates an Nmap object
- Runs an aggressive scan (-A) on the target
- Iterates through hosts, protocols, and ports
- Extracts:
  - Port
  - Protocol
  - Service name
  - Product
  - Version
  - CPE (if available)

Each port’s data is stored as a dictionary and returned as a list of findings.<br/><br/>
<img width="656" height="465" alt="image" src="https://github.com/user-attachments/assets/1e75ad18-1847-46be-9025-96c4218934b0" /> <br/><br/>



## Step 3. CPE Normalization

Older CPE formats often break modern CVE lookups.<br/>
To fix this, the script includes a function that:
- Detects outdated CPE strings
- Splits them into vendor/product components
- Converts them into CPE 2.3 format
- Fills missing fields with * <br/>
This ensures compatibility with the NVD API.

<img width="689" height="203" alt="image" src="https://github.com/user-attachments/assets/0434cd31-88eb-4af0-98db-cc86360e4aa0" />


## Step 4. Vulnerability Lookup
<img width="925" height="730" alt="image" src="https://github.com/user-attachments/assets/1f10be3f-b622-48ea-9079-5214db9e3257" /> <br/><br/>

**This function holds a list of vulnerabilities. It takes JSON data from the NVD and stores it into the data for our list. Such as CVE ID, Description and publication date which was used to filter out very old CVEs.Then we check if the cpe string is valid and updated to match it to a vulnerability. As I was having issues with this we made some backup lookups. I then attempted to search by product name if the CPE wouldnt show, and if that didnt work I went even broader and searched it by keyword to try and find some sort of information. After doing so the function returned a list of vulnerabilities with the corresponding data** 
<img width="979" height="669" alt="image" src="https://github.com/user-attachments/assets/00f0a952-f8fd-40cc-9502-dfa3e31a1aae" />
<br/><br/>

# Remidiation Guide
**I liked the idea of having a guide of remediation steps for common ports rather than a generic "update and patch", so I created a dictionary to hold common ports and associated remediation steps.**
<img width="658" height="843" alt="image" src="https://github.com/user-attachments/assets/c646a6c9-ff35-40fd-9194-e1a52eda3b6c" /> <br/><br/>
**This will come into play when the output is displayed to the pdf in the next section**

# Export function
**THis section was to export the findings into a neat looking pdf as if we were handing this to a client**
<img width="694" height="877" alt="image" src="https://github.com/user-attachments/assets/4cac4495-7e1d-4558-b6a2-c44f87ea977f" />

**We set the title of the pdf to be big and bold to stand out. We loop through the findings and print the host ip, port, procol, service name, product and CPE identifier. THe function then checks for vulnerabilities saved from the earlier check_vulns function and if they are found it displays them in red to stand out. It adds the CVE nuber, descriptiona and year. If none are found it prints "None are found" in green. THe function then goes through the ports to see if there are any remediation steps from the Remediation_Guidance dictionary, and prints them to the pdf.** <br/><br/>

# Last section is for the ip of the system/network you are running this on.
<img width="258" height="68" alt="image" src="https://github.com/user-attachments/assets/1705dd8a-c12e-4580-a3f1-c00c0c24fcac" />

**In this case I began by testing with my local machine but then turned on my Azure virtual machine and ran the scan on that machine. THis can be altered to ask for input from the user but for my testing I hard coded the Azure vm ip address. To get good results I enabled all trafiic inbound in the network security group and disabled the Windows Firewall**

# PDf report
<img width="777" height="862" alt="image" src="https://github.com/user-attachments/assets/88741578-8ae9-462a-ad80-85e1f893b40b" /> <br/><br/>

**Finally it prints the information to a pdf file which I will attatch here.** <br/><br/>

This lab was very insightfull and helped me refresh, my coding skills with python, nmap vulnerability scans and json/api calls

















