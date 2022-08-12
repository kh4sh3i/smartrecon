#!/bin/bash

sudo apt-get -y update
# sudo apt-get -y upgrade


sudo apt-get install -y libcurl4-openssl-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y jq
sudo apt-get install -y ruby-full
sudo apt-get install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt-get install -y build-essential libssl-dev libffi-dev python-dev
sudo apt-get install -y python-setuptools
sudo apt-get install -y libldns-dev
sudo apt-get install -y python3-pip
sudo apt-get install -y python-pip
sudo apt-get install -y python-dnspython
sudo apt-get install -y git
sudo apt-get install -y rename
sudo apt-get install -y xargs



#install go
if [[ -z "$GOPATH" ]];then
echo "It looks like go is not installed, would you like to install it now"
PS3="Please select an option : "
choices=("yes" "no")
select choice in "${choices[@]}"; do
        case $choice in
                yes)

					echo "Installing Golang"
					wget https://dl.google.com/go/go1.18.5.linux-amd64.tar.gz
					sudo tar -xvf go1.18.5.linux-amd64.tar.gz
					sudo rm -rf /usr/local/go
					sudo mv go /usr/local
					export GOROOT=/usr/local/go
					export GOPATH=$HOME/go
					export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
					echo 'export GOROOT=/usr/local/go' >> ~/.bash_profile
					echo 'export GOPATH=$HOME/go'	>> ~/.bash_profile			
					echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile	
					source ~/.bash_profile
					sleep 1
					break
					;;
				no)
					echo "Please install go and rerun this script"
					echo "Aborting installation..."
					exit 1
					;;
	esac	
done
fi


#create a tools folder in ~/
mkdir ~/tools
cd ~/tools/


echo "Installing crobat"
go install  github.com/cgboal/sonarsearch/cmd/crobat@latest
echo "done"


echo "Installing assetfinder"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo "done"


echo "Installing assetfinder"
go install  github.com/tomnomnom/assetfinder@latest
echo "done"




echo "installing dnsgen"
# sudo pip install urllib3==1.23 sudo pip install requests
git clone https://github.com/ProjectAnte/dnsgen
cd dnsgen
pip3 install -r requirements.txt
sudo python3 setup.py install
cd ~/tools/
echo "done"



echo "installing shuffledns"
go install  github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
echo "done"



echo "installing massdns"
git clone https://github.com/blechschmidt/massdns.git
cd ~/tools/massdns
make
cd ~/tools/
echo "done"



echo "installing httprobe"
go install github.com/tomnomnom/httprobe@latest
echo "done"



# echo "installing EyeWitness"
# git clone https://github.com/FortyNorthSecurity/EyeWitness.git
# cd EyeWitness/Python/setup/
# sudo ./setup.sh
# cd ~/tools/
# echo "done"



echo "installing gowitness"
go install github.com/sensepost/gowitness@latest
echo "done"




echo "installing waybackurls"
go install github.com/tomnomnom/waybackurls@latest
echo "done"


echo "installing httpx"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "done"


# echo "installing smartrecon"
# git clone https://github.com/kh4sh3i/smartrecon.git
# cd ~/tools/
# echo "done"


echo "installing feroxbuster"
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
echo "done"


echo "installing ffuf"
go install github.com/ffuf/ffuf@latest
echo "done"



echo "installing gf"
go install github.com/tomnomnom/gf@latest
echo "done"


echo "installing Gf-Patterns"
# echo 'source $GOPATH/pkg/mod/github.com/tomnomnom/gf*/gf-completion.bash' >> ~/.bashrc
# source ~/.bashrc 
mkdir .gf
sudo cp -r $GOPATH/pkg/mod/github.com/tomnomnom/gf*/examples/ ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns
sudo mv ~/tools/Gf-Patterns/*.json ~/.gf
echo "done"


echo "installing sqlmap"
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd ~/tools/
echo "done"


echo "installing naabu"
sudo apt install -y libpcap-dev
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
echo "done"

echo "installing unfurl"
go install github.com/tomnomnom/unfurl@latest
echo "done"



echo "installing notify"
go install github.com/projectdiscovery/notify/cmd/notify@latest
echo "done"


echo "installing nuclei"
go install  github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
echo "done"



echo "installing deduplicate"
go install github.com/nytr0gen/deduplicate@latest
echo "done"


echo "installing dalfox"
go install github.com/hahwul/dalfox/v2@latest
echo "done"


echo "installing ParamSpider"
git clone https://github.com/devanshbatham/ParamSpider
cd ParamSpider
pip3 install -r requirements.txt
cd ~/tools/
echo "done"


echo "installing qsreplace"
go install github.com/tomnomnom/qsreplace@latest
echo "done"


echo "installing interactsh"
go install  github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
echo "done"


echo "downloading Seclists"
cd ~/tools/
git clone https://github.com/danielmiessler/SecLists.git
cd ~/tools/SecLists/Discovery/DNS/
##THIS FILE BREAKS MASSDNS AND NEEDS TO BE CLEANED
cat dns-Jhaddix.txt | head -n -14 > clean-jhaddix-dns.txt
cd ~/tools/
echo "done"


sudo pip install urllib3==1.23 sudo pip install requests


echo -e "\n\n\n\n\n\n\n\n\n\n\nDone! All tools are set up in ~/tools"
ls -la
