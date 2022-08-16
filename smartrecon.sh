#!/bin/bash

dirsearchWordlist=~/tools/SecLists/Discovery/Web-Content/dirsearch.txt
massdnsWordlist=~/tools/SecLists/Discovery/DNS/clean-jhaddix-dns.txt
feroxbuster=~/tools/feroxbuster
paramspider=~/tools/ParamSpider/paramspider.py
server_ip=$(curl -s ifconfig.me)



red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
reset=`tput sgr0`

SECONDS=0
domain=
subreport=
usage() { 
  echo -e "Usage: sudo ./smartrecon.sh -d domain.com <option> 
  option:
    -a | --alt   : Additionally permutate subdomains	
    -b | --brute : Basic directory bruteforce
    -f | --fuzz  : SSRF/LFI/SQLi fuzzing	" 1>&2; exit 1; 
}


# check for help arguments or exit with no arguments
checkhelp(){
  while [ "$1" != "" ]; do
      case $1 in
          -h | --help ) usage exit;;
      esac
      shift
  done
}


# check for specifiec arguments (help)
checkargs(){
  while [ "$1" != "" ]; do
      case $1 in
          -a | --alt   )  alt="1";;
          -b | --brute )  brute="1";;
          -f | --fuzz  )  fuzz="1";;
      esac
      shift
  done
}


##### Main
if [ $# -eq 0 ]; then
    usage
    exit 1
else
  if [ $# -eq 1 ]; then
    checkhelp "$@"
  fi
fi

if [ $# -gt 1 ]; then
  checkargs "$@"
fi

domain=$2
if [ -z "${domain}" ]; then
   usage; exit 1;
fi


recon(){
  # public dataset search in project sonar (A rapid API for the Project Sonar dataset)
  echo -e "${green}1.Listing subdomains using crobat...${reset}"
  crobat -s $domain > ./$domain/$foldername/$domain.txt

  echo -e "${green}2.Listing subdomains using subfinder...${reset}"
  subfinder -silent  -d $domain -all | sort -u >> ./$domain/$foldername/$domain.txt 

  echo -e "${green}3.Listing subdomains using assetfinder...${reset}"
  assetfinder -subs-only $domain >> ./$domain/$foldername/$domain.txt

  # echo -e "${green}3.1.Listing subdomains using gau...${reset}"
  # gau=`gau -subs $domain | cut -d / -f3 >> ./$domain/$foldername/$domain.txt`


#  echo -e "5.excloude out of scope subdomain with hgnored.txt ..."
#  grep=`grep -vf ignored.txt domains.txt > temp.txt`
#  change=`mv temp.txt domains.txt`

#  echo -e "5.1.vertical discovery subdomains with amass..."
#  amass=`amass enum -d $domain -ip -src`

#  echo -e "5.2.horizantal discovery subdomains with amass..."
#  amass2=`amass intel -d $domain -whois`

#  echo -e "5.3.get new subdomains with amass track..."
#  amass3=`amass track -d $domain`
}

searchcrtsh(){
  echo "${green}Checking http://crt.sh ${reset}"
 ~/tools/massdns/scripts/ct.py $domain 2>/dev/null > ./$domain/$foldername/tmp.txt
 [ -s ./$domain/$foldername/tmp.txt ] && cat ./$domain/$foldername/tmp.txt | ~/tools/massdns/bin/massdns -r ~/tools/massdns/lists/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/crtsh.txt
 cat ./$domain/$foldername/$domain.txt | sort -u | ~/tools/massdns/bin/massdns -r ~/tools/massdns/lists/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/domaintemp.txt
}


permutatesubdomains(){
  cat ./$domain/$foldername/$domain.txt | dnsgen - | sort -u | tee ./$domain/$foldername/dnsgen.txt
  mv ./$domain/$foldername/dnsgen.txt ./$domain/$foldername/$domain.txt
}


dnsprobing(){
  echo "${green}Started dnsprobing with shuffledns...${reset}"
  cat ./$domain/$foldername/$domain.txt | sort -u |  shuffledns -d $domain -silent -r ~/tools/massdns/lists/resolvers.txt -o ./$domain/$foldername/mass.txt
  #  echo -e "4.1.Brute force all subdomain to find subdomain using shuffledns..."
  # shuffledns  -d $domain -silent -list ./$domain/$foldername/$domain.txt  -r ~/tools/massdns/lists/resolvers.txt -o ./$domain/$foldername/mass.txt
}


subdomain_takeover(){
  echo "${green}Started dns records check...${reset}"
  cat ./$domain/$foldername/mass.txt >> ./$domain/$foldername/temp.txt
  cat ./$domain/$foldername/domaintemp.txt >> ./$domain/$foldername/temp.txt
  cat ./$domain/$foldername/crtsh.txt >> ./$domain/$foldername/temp.txt


  cat ./$domain/$foldername/temp.txt | awk '{print $3}' | sort -u | while read line; do
  wildcard=$(cat ./$domain/$foldername/temp.txt | grep -m 1 $line)
  echo "$wildcard" >> ./$domain/$foldername/cleantemp.txt
  done

  cat ./$domain/$foldername/cleantemp.txt | grep CNAME >> ./$domain/$foldername/cnames.txt
  cat ./$domain/$foldername/cnames.txt | sort -u | while read line; do
  hostrec=$(echo "$line" | awk '{print $1}')
  if [[ $(host $hostrec | grep NXDOMAIN) != "" ]]
  then
  echo "${red}Check the following domain for NS takeover:  $line ${reset}"
  echo "$line" >> ./$domain/$foldername/pos.txt
  else
  echo -ne "working on it...\r"
  fi
  done
  sleep 1
  cat ./$domain/$foldername/$domain.txt > ./$domain/$foldername/alldomains.txt
  cat ./$domain/$foldername/cleantemp.txt | awk  '{print $1}' | while read line; do
  x="$line"
  echo "${x%?}" >> ./$domain/$foldername/alldomains.txt
  done
  sleep 1
}


checkhttprobe(){
  echo "Probing for live hosts with httprobe..."
  cat ./$domain/$foldername/alldomains.txt | sort -u | httprobe -c 50 -t 3000 >> ./$domain/$foldername/responsive.txt
  cat ./$domain/$foldername/responsive.txt | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | sort -u | while read line; do
  probeurl=$(cat ./$domain/$foldername/responsive.txt | sort -u | grep -m 1 $line)
  echo "$probeurl" >> ./$domain/$foldername/urllist.txt
  done
  echo "$(cat ./$domain/$foldername/urllist.txt | sort -u)" > ./$domain/$foldername/urllist.txt
  echo  "${yellow}Total of $(wc -l ./$domain/$foldername/urllist.txt | awk '{print $1}') live subdomains were found${reset}"
}


screenshots(){
  echo "${green}starting take screenshots ...${reset}"
  gowitness file -f ./$domain/$foldername/urllist.txt -P ./$domain/$foldername/screenshots/ --delay 5   -D ./$domain/$foldername/gowitness.sqlite3
  echo "${green}[screenshot] done.${reset}"
}


interesting(){
	echo -e "${green}find interesting data in site...${reset}"
	cat ./$domain/$foldername/urllist.txt | waybackurls | qsreplace  -a | tee ./$domain/$foldername/waybackurls.txt
  cat ./$domain/$foldername/waybackurls.txt | gf interestingEXT | grep -viE '(\.(js|css|pdf|svg|png|jpg|woff))' | sort -u | httpx -status-code -mc 200 -silent | awk '{ print $1}' > ./$domain/$foldername/wayback-data/interesting.txt
}

directory_bruteforce(){
  echo -e "${green}Starting directory bruteforce with FFUF...${reset}"
  # cat ./$domain/$foldername/urllist.txt | $feroxbuster --stdin --silent -s 200 -n -w $dirsearchWordlist -o ./$domain/$foldername/directory.txt
  
  for sub in $(cat ./$domain/$foldername/urllist.txt);
    do  
    echo "${yellow} $sub ${reset}"
    ffuf -w $dirsearchWordlist -u $sub/FUZZ  -ac -mc 200 -s -sf  | tee ./$domain/$foldername/reports/$(echo  "$sub" | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g').txt;
  done;
}


vulnscanner(){
  echo -e "${green}Starting vuln scanner with nuclei...${reset}"
  cat ./$domain/$foldername/urllist.txt | nuclei -tags exposure,unauth,cache -o ./$domain/$foldername/nuclei.txt -silent; notify -bulk -data ./$domain/$foldername/nuclei.txt -silent


  echo -e "${green}Starting up listen server...${reset}"
  interactsh-client  -v &> ./$domain/$foldername/listen_server.txt & SERVER_PID=$!
  sleep 5 # to properly start listen server
  LISTENSERVER=$(tail -n 1 ./$domain/$foldername/listen_server.txt)
  LISTENSERVER=$(echo $LISTENSERVER | cut -f2 -d ' ')
  echo "Listen server is up $LISTENSERVER with PID=$SERVER_PID"


  echo -e "${green}find SSRF vulnerability ...${reset}"
  cat ./$domain/$foldername/waybackurls.txt | gf ssrf | qsreplace https://$LISTENSERVER | httpx -silent | tee ./$domain/$foldername/ssrf_url.txt
  notify -bulk -data ./$domain/$foldername/ssrf_url.txt -silent

  # kill listen server
  kill_listen_server


  echo -e "${green}find Xss vulnerability ...${reset}"
  python3 $paramspider -d $domain -s TRUE -e jpg,jpeg,gif,css,js,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt,eot -q -o ./$domain/$foldername/xss_result.txt 
  cat ./$domain/$foldername/xss_result.txt | qsreplace  -a | httpx -silent -threads 500 -mc 200 |  dalfox pipe -S | tee ./$domain/$foldername/xss_raw_result.txt
  cat ./$domain/$foldername/xss_raw_result.txt | cut -d ' ' -f2 | tee ./$domain/$foldername/xss_result.txt; notify -bulk -data ./$domain/$foldername/xss_result.txt -silent

  # echo -e "${green}find sql injection with wayback ...${reset}"
  # python3 paramspider.py -d $domain -s TRUE -e woff,ttf,eot,css,js,png,svg,jpg | deduplicate --sort | httpx -silent | sqlmap

  # echo -e "${green}find open redirect vulnerability ...${reset}"
  # cat ./$domain/$foldername/waybackurls.txt | gf redirect | qsreplace  -a | httpx -silent |  while read domain; do python3 oralyzer.py -u $domain; done 

  # echo -e "${green}find CORS vulnerability ...${reset}"
  # echo https://google.com | hakrawler -u | httpx -silent | CorsMe 

  # echo -e "${green}find Prototype Pollution vulnerability ...${reset}"
  # echo https://google.com | hakrawler -u | httpx -silent | ppmap 

  # echo -e "${green}find dom xss with parameter pollution vulnerability ...${reset}"
  # cat ./$domain/$foldername/waybackurls.txt | httpx -silent | ppmap

}


kill_listen_server(){
  if [[ -n "$SERVER_PID" ]]; then
    echo "killing listen server $SERVER_PID..."
    kill -9 $SERVER_PID &> /dev/null || true
  fi
}



master_report()
{
   echo '<html>
    <head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">' >> ./$domain/$foldername/master_report.html
    echo "<title>Recon Report for $domain</title>
    <style>.status.redirect{color:#d0b200}.status.fivehundred{color:#DD4A68}.status.jackpot{color:#0dee00}img{padding:5px;width:360px}img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}pre{font-family:Inconsolata,monospace}pre{margin:0 0 20px}pre{overflow-x:auto}article,header,img{display:block}#wrapper:after,.blog-description:after,.clearfix:after{content:}.container{position:relative}html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}h1{margin:.67em 0}h1,h2{margin-bottom:20px}a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}.container,table{width:100%}.site-header{overflow:auto}.post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}p{line-height:1.5em}pre,table td{padding:10px}h2{padding-top:40px;font-weight:900}a{color:#00a0fc}body,html{height:100%}body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,'Helvetica Neue',Arial,sans-serif;font-size:24px}h1{font-size:35px}h2{font-size:28px}p{margin:0 0 30px}pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}.row{display:flex}.column{flex:100%}table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}table th{padding:0 10px 10px;text-align:left}.post-header,.post-title,.site-header{text-align:center}table tr{border-bottom:1px dotted #aeadad}::selection{background:#fff5b8;color:#000;display:block}::-moz-selection{background:#fff5b8;color:#000;display:block}.clearfix:after{display:table;clear:both}.container{max-width:100%}#wrapper{height:auto;min-height:100%;margin-bottom:-265px}#wrapper:after{display:block;height:265px}.site-header{padding:40px 0 0}.site-title{float:left;font-size:14px;font-weight:600;margin:0}.site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}.post-container-left{width:49%;float:left;margin:auto}.post-container-right{width:49%;float:right;margin:auto}.post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}.post-title{font-weight:900;margin:15px 0}.blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}.single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}body.dark{background-color:#1e2227;color:#fff}body.dark pre{background:#282c34}body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}input{font-family:Inconsolata,monospace} body.dark .status.redirect{color:#ecdb54} body.dark input{border:1px solid ;border-radius: 3px; background:#282c34;color: white} body.dark label{color:#f1f0ea} body.dark pre{color:#fff}</style>
    <script>
    document.addEventListener('DOMContentLoaded', (event) => {
      ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
    })
    </script>" >> ./$domain/$foldername/master_report.html
    echo '<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.1.0/material.min.css">
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.19/css/dataTables.material.min.css">
      <script type="text/javascript" src="https://code.jquery.com/jquery-3.3.1.js"></script>
    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.js"></script><script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/dataTables.material.min.js"></script>'>> ./$domain/$foldername/master_report.html
    echo '<script>$(document).ready( function () {
        $("#myTable").DataTable({
            "paging":   true,
            "ordering": true,
            "info":     false,
      "lengthMenu": [[10, 25, 50,100, -1], [10, 25, 50,100, "All"]],
        });
    } );</script></head>'>> ./$domain/$foldername/master_report.html



    echo '<body class="dark"><header class="site-header">
    <div class="site-title"><p>' >> ./$domain/$foldername/master_report.html
    echo "<a style=\"cursor: pointer\" onclick=\"localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\" title=\"Switch to light or dark theme\">🌓 Light|dark mode</a>
    </p>
    </div>
    </header>" >> ./$domain/$foldername/master_report.html


    echo '<div id="wrapper"><div id="container">' >> ./$domain/$foldername/master_report.html
    echo "<h2 class=\"post-title\" itemprop=\"name headline\">Recon Report for <a href=\"http://$domain\">$domain</a></h2>" >> ./$domain/$foldername/master_report.html
    echo "<p class=\"blog-description\">Generated by smartrecon on $(date) </p>" >> ./$domain/$foldername/master_report.html
    echo '<div class="container single-post-container">
    <article class="post-container-left" itemscope="" itemtype="http://schema.org/BlogPosting">
    <header class="post-header"></header>
    <div class="post-content clearfix" itemprop="articleBody">
    <h3>Total scanned subdomains</h3>
    <table id="myTable" class="stripe">
    <thead>
    <tr>
    <th>Subdomains</th>
    <th>Scanned Urls</th>
    </tr>
    </thead>
    <tbody>' >> ./$domain/$foldername/master_report.html


    cat ./$domain/$foldername/urllist.txt |  sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g'  | while read nline; do
    # diresults=$(ls ~/tools/dirsearch/reports/$nline/ | grep -v old)
    echo "<tr>
    <td><a href='http://$nline'>$nline</a></td>
    <td><a href='./reports/$nline.txt'>$(cat ./$domain/$foldername/reports/$nline.txt | wc -l)</a></td>
    </tr>" >> ./$domain/$foldername/master_report.html
    done
    echo "</tbody></table>
    <div><h3>Possible NS Takeovers</h3></div>
    <pre>" >> ./$domain/$foldername/master_report.html
    cat ./$domain/$foldername/pos.txt >> ./$domain/$foldername/master_report.html

    echo "</pre><div><h3>Wayback data</h3></div>" >> ./$domain/$foldername/master_report.html
    echo "<table><tbody>" >> ./$domain/$foldername/master_report.html
    [ -s ./$domain/$foldername/wayback-data/interesting.txt ] && echo "<tr><td><a href='./wayback-data/interesting.txt'>interestingEXT Urls</a></td></tr>" >> ./$domain/$foldername/master_report.html
    echo "</tbody></table>" >> ./$domain/$foldername/master_report.html


    echo "<div><h3>vuln scanner</h3></div>
    <table><tbody>
    <tr><td><a href='./nuclei.txt'>nuclei scanner</a></td></tr>
    <tr><td><a href='./xss_result.txt'>Xss vuln</a></td></tr>
    <tr><td><a href='./listen_server.txt'>OOB vuln</a></td></tr>
    <tr><td><a href='./ssrf_url.txt'>SSRF vuln</a></td></tr>
    </tbody></table></div>" >> ./$domain/$foldername/master_report.html



    echo '</article><article class="post-container-right" itemscope="" itemtype="http://schema.org/BlogPosting">
    <header class="post-header">
    </header>
    <div class="post-content clearfix" itemprop="articleBody">' >> ./$domain/$foldername/master_report.html
    echo "<h3><a href='http://$server_ip:30200'>View screanshots Report</a></h3>" >> ./$domain/$foldername/master_report.html
    #cat ./$domain/$foldername/ipaddress.txt >> ./$domain/$foldername/master_report.html
    echo "<h3>Dig Info</h3>
    <pre>
    $(dig $domain)
    </pre>" >> ./$domain/$foldername/master_report.html
    echo "<h3>Host Info</h3>
    <pre>
    $(host $domain)
    </pre>" >> ./$domain/$foldername/master_report.html
    echo "<h3>port scanning Results</h3>
    <pre>
      $(naabu -host $domain -silent -ec )
    </pre>
    </div></article></div>
    </div></div></body></html>" >> ./$domain/$foldername/master_report.html
}

logo(){
  #can't have a bash script without a cool logo :D
    echo "${yellow} 
#    _____ ___ ___   ____  ____   ______  ____     ___     __   ___   ____  
#   / ___/|   T   T /    T|    \ |      T|    \   /  _]   /  ] /   \ |    \ 
#  (   \_ | _   _ |Y  o  ||  D  )|      ||  D  ) /  [_   /  / Y     Y|  _  Y
#   \__  T|  \_/  ||     ||    / l_j  l_j|    / Y    _] /  /  |  O  ||  |  |
#   /  \ ||   |   ||  _  ||    \   |  |  |    \ |   [_ /   \_ |     ||  |  |
#   \    ||   |   ||  |  ||  .  Y  |  |  |  .  Y|     T\     |l     !|  |  |
#    \___jl___j___jl__j__jl__j\_j  l__j  l__j\_jl_____j \____j \___/ l__j__j${reset}"
}


cleantemp(){

    rm ./$domain/$foldername/temp.txt
  	rm ./$domain/$foldername/tmp.txt
    rm ./$domain/$foldername/domaintemp.txt
    rm ./$domain/$foldername/cleantemp.txt

}


main(){
if [ -z "${domain}" ]; then
domain=${subreport[1]}
foldername=${subreport[2]}
subd=${subreport[3]}
# report $domain $subdomain $foldername $subd; exit 1;
fi
  clear
  logo
  echo "${green}Scan for $domain start${reset}" | notify -silent
  if [ -d "./$domain" ]
  then
    echo "${red}This is a known target.${reset}"
  else
    mkdir ./$domain
  fi

  mkdir ./$domain/$foldername
  mkdir ./$domain/$foldername/reports/
  mkdir ./$domain/$foldername/wayback-data/
  mkdir ./$domain/$foldername/screenshots/
  touch ./$domain/$foldername/crtsh.txt
  touch ./$domain/$foldername/mass.txt
  touch ./$domain/$foldername/cnames.txt
  touch ./$domain/$foldername/pos.txt
  touch ./$domain/$foldername/alldomains.txt
  touch ./$domain/$foldername/temp.txt
  touch ./$domain/$foldername/tmp.txt
  touch ./$domain/$foldername/domaintemp.txt
  touch ./$domain/$foldername/ipaddress.txt
  touch ./$domain/$foldername/cleantemp.txt
  touch ./$domain/$foldername/directory.txt
  touch ./$domain/$foldername/master_report.html

  cleantemp
  recon $domain
  searchcrtsh $domain
  if [[ -n "$alt" ]]; then 
    permutatesubdomains $domain
  fi
  dnsprobing $domain
  subdomain_takeover $domain
	checkhttprobe $domain
  screenshots $domain
  interesting $domain
  if [[ -n "$brute" ]]; then 
    directory_bruteforce $domain
  fi
  if [[ -n "$fuzz" ]]; then 
    vulnscanner $domain
  fi
  master_report $domain
  echo "${green}Scan for $domain finished successfully${reset}" | notify -silent
  duration=$SECONDS
  echo "Scan completed in : $(($duration / 60)) minutes and $(($duration % 60)) seconds." | notify -silent
  cleantemp
  echo "${green}server screanshots start ${reset}"
  cd ./$domain/$foldername/ &&  gowitness server -a $server_ip:30200
  stty sane
  tput sgr0
}

todate=$(date +%F-%T)
path=$(pwd)
foldername=$todate
source ~/.bash_profile
main $domain
