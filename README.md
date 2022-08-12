<img src="img/logo.png" style="width: 300px; display: block; margin: 0px auto;" />

# smartrecon
smartrecon is a script written in Bash, it is intended to automate some tedious tasks of reconnaissance and information gathering

## Usage
```
./smartrecon.sh -d domain.com
```

## Main Features
* Create a dated folder with recon notes
* Grab subdomains using:
    * subfinder, assetfinder, SonarSearch, cert.sh
    * dnsgen , shuffledns , massdns
* Find any CNAME records pointing to unused cloud services like aws
* Probe for live hosts over ports 80/443
* Grab a screenshots of responsive hosts with gowitness
* Extract wayback import data
* Perform naabu on specific ports
* Perform dirsearch for all subdomains
* find exposure data with nuclei scanner
* find XSS, SSRF, cache poisoning vulnerability
* send notifiaction wthi notify tools to discord,telegram,...
* Generate a HTML report with output from the tools above


## System Requirements
* Recommended to run on vps with 1VCPU and 2GB ram.

## Installation & Requirements
```
git clone https://github.com/kh4sh3i/smartrecon.git
cd smartrecon
chmod +x install.sh
./install.sh
```


## Tools
*  SonarSearch
*  subfinder
*  assetfinder
*  dnsgen
*  shuffledns
*  Massdns
*  Httprobe
*  goWitness
*  Waybackurls
*  httpx
*  gf
*  interestingEXT
*  feroxbuster
*  naabu
*  sqlmap-dev
*  Unfurl
*  nuclei
*  deduplicate
*  dalfox
*  ParamSpider
*  qsreplace
*  notify
*  Seclists collection

## Vulnerability 
this is not only recon tools ! we automate find bug for your :D
today we can find below bug :
* XSS
* SSRF
* data exposure
* Broken authentication
* cache poisoning


### Tips
for send notification you should config ($HOME/.config/notify/provider-config.yaml) with discord webhook ulr. read [Notification system for your Bug Bounty Automation](https://hakin9.org/notification-system-for-your-bug-bounty-automation-by-anubhav-singh/)


### Thanks
* [nahamsec - Ben Sadeghipour](https://github.com/nahamsec)
* [Tom Hudson - Tomonomnom](https://github.com/tomnomnom)
