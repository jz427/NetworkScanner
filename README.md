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

# Step 1. Library Imports

- nmap → to perform aggressive scans and extract service/version data
- requests → to query the NVD API for vulnerabilities
- FPDF → to generate a clean, readable PDF report<br/>

These three components form the core of the scanning → analysis → reporting workflow.

<img width="347" height="113" alt="image" src="https://github.com/user-attachments/assets/38fe6f12-9d84-4c6b-8d29-85d59d398f4e" /> <br/><br/>







**For this project I needed to import the Nmap library in order to run the network scan and get the info needed.**
**The requests library was needed to pull the vulnerability info from the web for our report.**
**Finally we needed the FPDF library in order to print out a nice looking report to imagine we were giving it to a client** <br/><br/>

## We then created the scan function
<img width="656" height="465" alt="image" src="https://github.com/user-attachments/assets/1e75ad18-1847-46be-9025-96c4218934b0" /> <br/><br/>

**We create a function to begin our scan. We create a object using the nmap library. We then call the object to run a scan of our target/s using the aggressive, detect services version of Nmap. We create a list to hold the results and then iterate through the hosts(in this case one). The function continues to iterate through the protocols such as udp or tcp, and finally the port. We then collect this infomation including the service, product, version and cpe(Common Platform Enumeration identifier) which helps us find CVEs. It then returns a list of dictionaries, one for each port** <br/><br/>

**When running this I was having trouble with certain CVE and CPE formats linking together, therefore I needed to make sure the script could handle the old and new CPEs. I did this by creating a function that converts old CPE strings into the modern fomrat of CPE 2.3** <br/><br/>
<img width="689" height="203" alt="image" src="https://github.com/user-attachments/assets/0434cd31-88eb-4af0-98db-cc86360e4aa0" />

**This function first checks if the CPE is in the old format and then splits it into sections. This helps us extract the vendor and product and convert it to the updated CPE format. We used * for unspecified fields. If the format wasnt old it wuldnt modify the CPE.** <br/>

## Function to check the national Vulnerability Databse to pull info (1 of 2 pictures)
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

















