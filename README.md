# NetworkScanner


## Objective


This labs purpose was to code a network scanner to see possible vulnerabilities, associated CVE's and remediation steps
### Skills Learned


- Python Refresher
- Nmap
- leveraging Ai
  

### Tools Used


- Visual Studio Code
- Python
- Microsoft Copilot
- Json

## Steps

**I began coding and making corrections with copilots help by knowing what to provide it with and how to formulate questions. A lot of the info and code it gave was incorrect so it took a lot of testing and back and forth** <br/><br/>

**I will go through each section of code and explain the reasoning for it** <br/><br/>

## Lets start with the libraries
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

**This function holds a list of vulnerabilities. It takes JSON data from the NVD and stores it into the data for our list. Such as CVE ID, Description and publication date which was used to filter out very old CVEs.Then we check if the cpe string is valid and updated to match it to a vulnerability. As I was having issues with this we made some backup lookups. I then attempted to search by product name if the CPE wouldnt show, and if that didnt work I went even broader and searched it by keyword to try and find some sort of information. After doing so the function returned a list of vulnerabilities with the corresponding data** <br/><br/>










