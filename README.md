<h1 align="center">
  <br>
  <a href=""><img src="/img/logo.png" alt="" width="300px;"></a>
  <br>
  <img src="https://img.shields.io/badge/PRs-welcome-blue">
  <img src="https://img.shields.io/github/last-commit/kh4sh3i/smartrecon"> 
  <img src="https://img.shields.io/github/commit-activity/m/kh4sh3i/smartrecon">
  <a href="https://twitter.com/intent/follow?screen_name=kh4sh3i_"><img src="https://img.shields.io/twitter/follow/kh4sh3i_?style=flat&logo=twitter"></a>
  <a href="https://github.com/kh4sh3i"><img src="https://img.shields.io/github/stars/kh4sh3i?style=flat&logo=github"></a>
</h1>

# smartrecon
smartrecon is a script written in Bash, it is intended to automate some tedious tasks of reconnaissance and information gathering

## Usage
```
sudo ./smartrecon.sh -d domain.com <option>
  option:
    -a | --alt   : Additionally permutate subdomains	
    -b | --brute : Basic directory bruteforce
    -f | --fuzz  : SSRF/XSS/Nuclei/CORS/prototype fuzzing	
    -s | --ssrf  : SSRF fuzzing	
    -x | --xss   : XSS fuzzing	  
    -n | --nuclei: Nuclei fuzzing	
    -c | --cors  : Cors fuzzing	  
    -p | --pp    : prototype pollution fuzzing	

```

## Main Features
* Create a dated folder with recon notes
* Grab subdomains using:
    * subfinder, assetfinder, SonarSearch, cert.sh
    * dnsgen , shuffledns , massdns
* Find any CNAME records pointing to unused cloud services like aws
* Probe for live hosts with shuffledns and fresh resolver
* Web servers hunting [httpx] over top 50 ports
* Grab a screenshots of responsive hosts with gowitness
* Extract wayback import data
* Perform naabu on specific ports
* Perform dirsearch for all subdomains
* find exposure data with nuclei scanner
* find XSS, SSRF, cache poisoning vulnerability
* send notifiaction wthi notify tools to discord,telegram,...
* Generate a HTML report with output from the tools above



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
*  Fresh Resolvers
*  shuffledns
*  Massdns
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
*  dalfox
*  ParamSpider
*  qsreplace
*  notify
*  Seclists collection
*  CorsMe
*  ppmap




## Vulnerability 
this is not only recon tools ! we automate find bug for your :D
today we can find below bug :
* XSS
* SSRF
* data exposure
* Broken authentication
* cache poisoning
* subdomain takeover
* Cors 
* prototype pollution


### Tips
for send notification you should config ($HOME/.config/notify/provider-config.yaml) with discord webhook ulr.


## System Requirements
* Recommended to run on vps with 1VCPU and 2GB ram.


## Contributing
If you want to contribute to a project and make it better, your help is very welcome. 

## product Roadmap
* add open redirect scanner
* add sql injection scanner
* increase performance



### Thanks
* [nahamsec - Ben Sadeghipour](https://github.com/nahamsec)
* [Tom Hudson - Tomonomnom](https://github.com/tomnomnom)
* [Jason Haddix](https://github.com/jhaddix)
* [ProjectDiscovery](https://github.com/projectdiscovery)
* [Orange Cyberdefense](https://github.com/sensepost)
* [HAHWUL](https://github.com/hahwul)
* [Devansh Batham](https://github.com/devanshbatham)
* [Daniel Miessler](https://github.com/danielmiessler)
