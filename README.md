# smartrecon
smartrecon is a script written in Bash, it is intended to automate some tedious tasks of reconnaissance and information gathering

## Usage
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
* find exposure data with nuclei scanner
* find xss vulnerability
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
*  EyeWitness
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


### Tips
for send notification you should config ($HOME/.config/notify/provider-config.yaml) with discord webhook ulr. read [Notification system for your Bug Bounty Automation](https://hakin9.org/notification-system-for-your-bug-bounty-automation-by-anubhav-singh/)


### Thanks
* [nahamsec - Ben Sadeghipour](https://github.com/nahamsec)
* [Tom Hudson - Tomonomnom](https://github.com/tomnomnom)
