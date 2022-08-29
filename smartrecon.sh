#!/bin/bash

dirsearchWordlist=~/tools/SecLists/Discovery/Web-Content/dirsearch.txt
feroxbuster=~/tools/feroxbuster
paramspider=~/tools/ParamSpider/paramspider.py
HTTPXCALL="httpx -silent -no-color -random-agent -ports 80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672"
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
    -f | --fuzz  : SSRF/XSS/Nuclei/CORS/prototype fuzzing	
    -s | --ssrf  : SSRF fuzzing	
    -x | --xss   : XSS fuzzing	  
    -n | --nuclei: Nuclei fuzzing	
    -c | --cors  : CORS fuzzing	
    -p | --pp    : prototype pollution fuzzing" 1>&2; exit 1; 
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
          -f | --fuzz  )  ssrf="1" xss="1" nuclei="1" corse="1" prototype="1" ;;
          -s | --ssrf  )  ssrf="1";;
          -x | --xss   )  xss="1";;
          -n | --nuclei)  nuclei="1";;
          -c | --cors  )  cors="1";;
          -p | --pp    )  prototype="1";;
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


downloader(){
  wget -q  https://raw.githubusercontent.com/kh4sh3i/Fresh-Resolvers/master/resolvers.txt  -O ./$domain/$foldername/resolvers.txt
  wget -q  https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O ./$domain/$foldername/dns_wordlist.txt
}


oob_server(){
  echo -e "${green}Starting up listen server...${reset}"
  interactsh-client  -v &> ./$domain/$foldername/listen_server.txt & SERVER_PID=$!
  sleep 5 # to properly start listen server
  LISTENSERVER=$(tail -n 1 ./$domain/$foldername/listen_server.txt)
  LISTENSERVER=$(echo $LISTENSERVER | cut -f2 -d ' ')
  echo "Listen server is up $LISTENSERVER with PID=$SERVER_PID"
}


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
 [ -s ./$domain/$foldername/tmp.txt ] && cat ./$domain/$foldername/tmp.txt | ~/tools/massdns/bin/massdns -r ./$domain/$foldername/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/crtsh.txt
}


permutatesubdomains(){
  echo "${green}Started dns permutation with dnsgen...${reset}"
  cat ./$domain/$foldername/$domain.txt | dnsgen - | sort -u | tee ./$domain/$foldername/dnsgen.txt
  mv ./$domain/$foldername/dnsgen.txt ./$domain/$foldername/$domain.txt
}


dnsprobing(){
  echo "${green}Started dnsprobing with shuffledns for live host...${reset}"
  cat ./$domain/$foldername/$domain.txt | sort -u |  shuffledns -d $domain -silent -r ./$domain/$foldername/resolvers.txt -o ./$domain/$foldername/shuffledns.txt 
  echo  "${yellow}Total of $(wc -l ./$domain/$foldername/shuffledns.txt | awk '{print $1}') live subdomains were found${reset}"


  # echo "${green}Started Subdomain Bruteforcing with shuffledns...${reset}"
  # shuffledns  -d $domain -silent -list ./$domain/$foldername/dns_wordlist.txt  -r ./$domain/$foldername/resolvers.txt -o ./$domain/$foldername/sub_brute.txt
  # echo  "${yellow}Total of $(wc -l ./$domain/$foldername/sub_brute.txt | awk '{print $1}') live subdomains were found${reset}"
}


subdomain_takeover(){
  cat ./$domain/$foldername/shuffledns.txt >> ./$domain/$foldername/temp.txt
  # cat ./$domain/$foldername/sub_brute.txt >> ./$domain/$foldername/temp.txt
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
  echo "$line" >> ./$domain/$foldername/domain_takeover.txt
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
  echo "${green}Web servers hunting [httpx] Domain probe testing...${reset}"
  cat ./$domain/$foldername/$domain.txt | sort -u | $HTTPXCALL -o ./$domain/$foldername/subdomain_live.txt
}


screenshots(){
  echo "${green}starting take screenshots ...${reset}"
  gowitness file -f ./$domain/$foldername/subdomain_live.txt -P ./$domain/$foldername/screenshots/ --delay 5   -D ./$domain/$foldername/gowitness.sqlite3
  echo "${green}[screenshot] done.${reset}"
}


getgau(){
  echo "${green}fetch url from wayback,commoncrawl,otx,urlscan...${reset}"
  cat ./$domain/$foldername/subdomain_live.txt | gau -b jpg,jpeg,gif,css,js,tif,tiff,png,ttf,woff,woff2,ico,svg,eot  | qsreplace -a | tee ./$domain/$foldername/gau_output.txt
  echo "${green}gau done.${reset}"
}



get_interesting(){
	echo -e "${green}find interesting data in site...${reset}"
  cat ./$domain/$foldername/gau_output.txt | gf interestingEXT | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200 -silent | awk '{ print $1}' > ./$domain/$foldername/interesting.txt
}


directory_bruteforce(){
  echo -e "${green}Starting directory bruteforce with FFUF...${reset}"
  # cat ./$domain/$foldername/subdomain_live.txt | $feroxbuster --stdin --silent -s 200 -n -w $dirsearchWordlist -o ./$domain/$foldername/directory.txt
  
  for sub in $(cat ./$domain/$foldername/subdomain_live.txt);
    do  
    echo "${yellow} $sub ${reset}"
    ffuf -w $dirsearchWordlist -u $sub/FUZZ  -ac -mc 200 -s -sf  | tee ./$domain/$foldername/reports/$(echo  "$sub" | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g').txt;
  done;
}


NucleiScanner(){
  echo -e "${green}Starting vuln scanner with nuclei...${reset}"
  # cat ./$domain/$foldername/subdomain_live.txt | nuclei -tags exposure,unauth,cache -o ./$domain/$foldername/nuclei.txt -silent; notify -bulk -data ./$domain/$foldername/nuclei.txt -silent

  nuclei -silent -iserver "https://$LISTENSERVER" \
    -o ./$domain/$foldername/nuclei.txt \
    -l ./$domain/$foldername/subdomain_live.txt \
    -exclude-templates $HOME/nuclei-templates/misconfiguration/http-missing-security-headers.yaml \
    -exclude-templates $HOME/nuclei-templates/miscellaneous/old-copyright.yaml \
    -t $HOME/nuclei-templates/vulnerabilities/ \
    -t $HOME/nuclei-templates/cnvd/ \
    -t $HOME/nuclei-templates/iot/ \
    -t $HOME/nuclei-templates/cves/2014/ \
    -t $HOME/nuclei-templates/cves/2015/ \
    -t $HOME/nuclei-templates/cves/2016/ \
    -t $HOME/nuclei-templates/cves/2017/ \
    -t $HOME/nuclei-templates/cves/2018/ \
    -t $HOME/nuclei-templates/cves/2019/ \
    -t $HOME/nuclei-templates/cves/2020/ \
    -t $HOME/nuclei-templates/cves/2021/ \
    -t $HOME/nuclei-templates/cves/2022/ \
    -t $HOME/nuclei-templates/misconfiguration/ \
    -t $HOME/nuclei-templates/network/ \
    -t $HOME/nuclei-templates/miscellaneous/ \
    -t $HOME/nuclei-templates/takeovers/ \
    -t $HOME/nuclei-templates/default-logins/ \
    -t $HOME/nuclei-templates/exposures/ \
    -t $HOME/nuclei-templates/exposed-panels/ \
    -t $HOME/nuclei-templates/fuzzing/

  echo -e "${green}Finished nuclei scanner${reset}"
  notify -bulk -data ./$domain/$foldername/nuclei.txt -silent
}


SSRF_Scanner(){
  echo -e "${green}find SSRF vulnerability ...${reset}"
  cat ./$domain/$foldername/gau_output.txt | gf ssrf | qsreplace https://$LISTENSERVER | httpx -silent 
  notify -bulk -data ./$domain/$foldername/listen_server.txt -silent
}


XSS_Scanner(){
  echo -e "${green}find Xss vulnerability ...${reset}"
  # python3 $paramspider -d $domain -s TRUE -e jpg,jpeg,gif,css,js,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt,eot -q -o ./$domain/$foldername/xss_result.txt 
  cat ./$domain/$foldername/gau_output.txt | gf xss | qsreplace  -a | httpx -silent -threads 500 -mc 200 |  dalfox pipe -S | tee ./$domain/$foldername/xss_raw_result.txt
  cat ./$domain/$foldername/xss_raw_result.txt | cut -d ' ' -f2 | tee ./$domain/$foldername/xss_result.txt; notify -bulk -data ./$domain/$foldername/xss_result.txt -silent
}


CORS_Scanner(){
  echo -e "${green}find CORS vulnerability ...${reset}"
  # echo https://google.com | hakrawler -u | httpx -silent | CorsMe 
  cat ./$domain/$foldername/gau_output.txt | qsreplace  -a | httpx -silent -threads 500 -mc 200 | CorsMe - t 70 -output ./$domain/$foldername/cors_result.txt
}


Prototype_Pollution_Scanner(){
  echo -e "${green}find Prototype Pollution vulnerability ...${reset}"
  cat ./$domain/$foldername/gau_output.txt | qsreplace  -a | httpx -silent -threads 500 -mc 200 | ppmap | tee ./$domain/$foldername/prototype_pollution_result.txt
}



# echo -e "${green}find sql injection with wayback ...${reset}"
# python3 paramspider.py -d $domain -s TRUE -e woff,ttf,eot,css,js,png,svg,jpg | deduplicate --sort | httpx -silent | sqlmap




# echo -e "${green}find open redirect vulnerability ...${reset}"
# cat ./$domain/$foldername/gau_output.txt | gf redirect | qsreplace  -a | httpx -silent |  while read domain; do python3 oralyzer.py -u $domain; done 




kill_listen_server(){
  if [[ -n "$SERVER_PID" ]]; then
    echo "killing listen server $SERVER_PID..."
    kill -9 $SERVER_PID &> /dev/null || true
  fi
}



report()
{
   echo '<html>
    <head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">' >> ./$domain/$foldername/html_report.html
    echo "<title>Recon Report for $domain</title>
    <style>.status.redirect{color:#d0b200}.status.fivehundred{color:#DD4A68}.status.jackpot{color:#0dee00}img{padding:5px;width:360px}img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}pre{font-family:Inconsolata,monospace}pre{margin:0 0 20px}pre{overflow-x:auto}article,header,img{display:block}#wrapper:after,.blog-description:after,.clearfix:after{content:}.container{position:relative}html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}h1{margin:.67em 0}h1,h2{margin-bottom:20px}a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}.container,table{width:100%}.site-header{overflow:auto}.post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}p{line-height:1.5em}pre,table td{padding:10px}h2{padding-top:40px;font-weight:900}a{color:#00a0fc}body,html{height:100%}body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,'Helvetica Neue',Arial,sans-serif;font-size:24px}h1{font-size:35px}h2{font-size:28px}p{margin:0 0 30px}pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}.row{display:flex}.column{flex:100%}table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}table th{padding:0 10px 10px;text-align:left}.post-header,.post-title,.site-header{text-align:center}table tr{border-bottom:1px dotted #aeadad}::selection{background:#fff5b8;color:#000;display:block}::-moz-selection{background:#fff5b8;color:#000;display:block}.clearfix:after{display:table;clear:both}.container{max-width:100%}#wrapper{height:auto;min-height:100%;margin-bottom:-265px}#wrapper:after{display:block;height:265px}.site-header{padding:40px 0 0}.site-title{float:left;font-size:14px;font-weight:600;margin:0}.site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}.post-container-left{width:49%;float:left;margin:auto}.post-container-right{width:49%;float:right;margin:auto}.post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}.post-title{font-weight:900;margin:15px 0}.blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}.single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}body.dark{background-color:#1e2227;color:#fff}body.dark pre{background:#282c34}body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}input{font-family:Inconsolata,monospace} body.dark .status.redirect{color:#ecdb54} body.dark input{border:1px solid ;border-radius: 3px; background:#282c34;color: white} body.dark label{color:#f1f0ea} body.dark pre{color:#fff}</style>
    <script>
    document.addEventListener('DOMContentLoaded', (event) => {
      ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
    })
    </script>" >> ./$domain/$foldername/html_report.html
    echo '<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.1.0/material.min.css">
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.19/css/dataTables.material.min.css">
      <script type="text/javascript" src="https://code.jquery.com/jquery-3.3.1.js"></script>
    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.js"></script><script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/dataTables.material.min.js"></script>'>> ./$domain/$foldername/html_report.html
    echo '<script>$(document).ready( function () {
        $("#myTable").DataTable({
            "paging":   true,
            "ordering": true,
            "info":     false,
      "lengthMenu": [[10, 25, 50,100, -1], [10, 25, 50,100, "All"]],
        });
    } );</script></head>'>> ./$domain/$foldername/html_report.html



    echo '<body class="dark"><header class="site-header">
    <div class="site-title"><p>' >> ./$domain/$foldername/html_report.html
    echo "<a style=\"cursor: pointer\" onclick=\"localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\" title=\"Switch to light or dark theme\">🌓 Light|dark mode</a>
    </p>
    </div>
    </header>" >> ./$domain/$foldername/html_report.html


    echo '<div id="wrapper"><div id="container">' >> ./$domain/$foldername/html_report.html
    echo "<h2 class=\"post-title\" itemprop=\"name headline\">Recon Report for <a href=\"http://$domain\">$domain</a></h2>" >> ./$domain/$foldername/html_report.html
    echo "<p class=\"blog-description\">Generated by smartrecon on $(date) </p>" >> ./$domain/$foldername/html_report.html
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
    <tbody>' >> ./$domain/$foldername/html_report.html


    cat ./$domain/$foldername/subdomain_live.txt |  sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g'  | while read nline; do
    # diresults=$(ls ~/tools/dirsearch/reports/$nline/ | grep -v old)
    echo "<tr>
    <td><a href='http://$nline'>$nline</a></td>
    <td><a href='./reports/$nline.txt'>$(cat ./$domain/$foldername/reports/$nline.txt | wc -l)</a></td>
    </tr>" >> ./$domain/$foldername/html_report.html
    done
    echo "</tbody></table>
    <div><h3>Possible NS Takeovers</h3></div>
    <pre>" >> ./$domain/$foldername/html_report.html
    cat ./$domain/$foldername/domain_takeover.txt >> ./$domain/$foldername/html_report.html

    echo "</pre><div><h3>Wayback data</h3></div>" >> ./$domain/$foldername/html_report.html
    echo "<table><tbody>" >> ./$domain/$foldername/html_report.html
    [ -s ./$domain/$foldername/interesting.txt ] && echo "<tr><td><a href='./interesting.txt'>interestingEXT Urls</a></td></tr>" >> ./$domain/$foldername/html_report.html
    echo "</tbody></table>" >> ./$domain/$foldername/html_report.html


    echo "<div><h3>vuln scanner</h3></div>
    <table><tbody>
    <tr><td><a href='./nuclei.txt'>nuclei scanner</a></td></tr>
    <tr><td><a href='./xss_result.txt'>Xss vuln</a></td></tr>
    <tr><td><a href='./listen_server.txt'>OOB SSRF vuln</a></td></tr>
    <tr><td><a href='./cors_result.txt'>CORS vuln</a></td></tr>
    <tr><td><a href='./prototype_pollution_result.txt'>Prototype Pollution vuln</a></td></tr>
    </tbody></table></div>" >> ./$domain/$foldername/html_report.html



    echo '</article><article class="post-container-right" itemscope="" itemtype="http://schema.org/BlogPosting">
    <header class="post-header">
    </header>
    <div class="post-content clearfix" itemprop="articleBody">' >> ./$domain/$foldername/html_report.html
    echo "<h3><a href='http://$server_ip:30200'>View screanshots Report</a></h3>" >> ./$domain/$foldername/html_report.html
    echo "<h3>Dig Info</h3>
    <pre>
    $(dig $domain)
    </pre>" >> ./$domain/$foldername/html_report.html
    echo "<h3>Host Info</h3>
    <pre>
    $(host $domain)
    </pre>" >> ./$domain/$foldername/html_report.html
    echo "<h3>port scanning Results</h3>
    <pre> " >> ./$domain/$foldername/html_report.html
    naabu -host $domain -silent -ec 
    echo "</pre>
    </div></article></div>
    </div></div></body></html>" >> ./$domain/$foldername/html_report.html
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
    rm ./$domain/$foldername/cleantemp.txt
    rm ./$domain/$foldername/cnames.txt
    rm ./$domain/$foldername/xss_raw_result.txt
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
  mkdir ./$domain/$foldername/screenshots/
  touch ./$domain/$foldername/crtsh.txt
  touch ./$domain/$foldername/shuffledns.txt
  touch ./$domain/$foldername/cnames.txt
  touch ./$domain/$foldername/domain_takeover.txt
  touch ./$domain/$foldername/temp.txt
  touch ./$domain/$foldername/tmp.txt
  touch ./$domain/$foldername/cleantemp.txt
  touch ./$domain/$foldername/interesting.txt
  touch ./$domain/$foldername/directory.txt
  touch ./$domain/$foldername/xss_raw_result.txt
  touch ./$domain/$foldername/gau_output.txt
  # touch ./$domain/$foldername/sub_brute.txt
  touch ./$domain/$foldername/alldomains.txt
  touch ./$domain/$foldername/html_report.html

  cleantemp
  downloader
  oob_server
  recon $domain
  searchcrtsh $domain
  if [[ -n "$alt" ]]; then 
    permutatesubdomains $domain
  fi
  dnsprobing $domain
  subdomain_takeover $domain
	checkhttprobe $domain
  screenshots $domain
  getgau $domain
  get_interesting $domain
  if [[ -n "$brute" ]]; then 
    directory_bruteforce $domain
  fi
  if [[ -n "$nuclei" ]]; then 
    NucleiScanner $domain
  fi
  if [[ -n "$ssrf" ]]; then 
    SSRF_Scanner $domain
  fi
  if [[ -n "$xss" ]]; then 
    XSS_Scanner $domain
  fi
  if [[ -n "$cors" ]]; then 
    CORS_Scanner $domain
  fi
  if [[ -n "$prototype" ]]; then 
    Prototype_Pollution_Scanner $domain
  fi


  report $domain
  echo "${green}Scan for $domain finished successfully${reset}" | notify -silent
  duration=$SECONDS
  echo "Scan completed in : $(($duration / 60)) minutes and $(($duration % 60)) seconds." | notify -silent
  cleantemp
    # kill listen server
  kill_listen_server
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
