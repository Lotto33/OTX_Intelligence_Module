This Intelligence module uses the OTX AlienVault database of malicious urls, ip addresses, domains, hashes and files

This module allows one to check if a ip, url, domain, hash or file is malicious and record the results to a log

Steps to run:

1. If OTXv2 not installed in the terminal run `pip install OTXv2`
2. In `main.py` replace with your OTX API key. To get one make an account at `https://otx.alienvault.com/`
3. cd /path/to/your/project/directory
4. enter a terminal 
5. GENERAL FORMAT TO RUN = `python3 main.py -(SCAN MODE) FILE/IP/URL/DOMAIN/HASH`

    - url example
    `python3 main.py -url https://suspicious-website.xyz`
    - domain example
    - `-host www.google.com`
    - ip example
    - `python3 main.py -ip 8.8.8.8`
    - hash example (MD5, SHA1)
    `python3 main.py -hash 7b42b35832855ab4ff37ae9b8fa9e571`
    - file example
    - `python3 main.py -file /path/to/your/file.exe`

    