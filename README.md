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


