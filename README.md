# smartrecon
smartrecon is a script written in Bash, it is intended to automate some tedious tasks of reconnaissance and information gathering

# Usage
```
./smartrecon.sh -d domain.com
```

## Main Features
* Create a dated folder with recon notes
* Grab subdomains using:
    * subfinder, cert.sh
    * dnsgen , shuffledns , massdns
* Find any CNAME records pointing to unused cloud services like aws
* Probe for live hosts over ports 80/443
* Grab a screenshots of responsive hosts with eyewitness
* Extract wayback import data
* Perform naabu on specific ports
* Perform dirsearch for all subdomains
* Generate a HTML report with output from the tools above
