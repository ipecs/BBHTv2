#!/bin/bash

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

echo "${RED} ######################################################### ${RESET}"
echo "${RED} #                 TOOLS FOR BUG BOUNTY                  # ${RESET}"
echo "${RED} ######################################################### ${RESET}"
logo(){
echo "${BLUE}
                ___ ___ _  _ _____     ___
               | _ ) _ ) || |_   _|_ _|_  )
               | _ \ _ \ __ | | | \ V // /
               |___/___/_||_| |_|  \_//___| ${RESET}"
}
logo
echo ""
echo "${GREEN} Tools created by the best people in the InfoSec Community ${RESET}"
echo "${GREEN}                   Thanks to everyone!                     ${RESET}"
echo ""


echo "${GREEN} [+] Updating and installing dependencies ${RESET}"
echo ""
{
sudo apt-get -y update
sudo apt-get -y upgrade

sudo add-apt-repository -y ppa:apt-fast/stable < /dev/null
sudo echo debconf apt-fast/maxdownloads string 16 | sudo debconf-set-selections
sudo echo debconf apt-fast/dlflag boolean true | sudo debconf-set-selections
sudo echo debconf apt-fast/aptmanager string apt-get | sudo debconf-set-selections
sudo apt install -y apt-fast
sudo apt install -y aptitude gnupg

#Entry for kali repo's
sudo sh -c "echo 'deb https://http.kali.org/kali kali-rolling main non-free contrib' > /etc/apt/sources.list.d/kali.list"
wget 'https://archive.kali.org/archive-key.asc'
sudo apt-key add archive-key.asc
sudo sh -c "echo 'Package: *'>/etc/apt/preferences.d/kali.pref; echo 'Pin: release a=kali-rolling'>>/etc/apt/preferences.d/kali.pref; echo 'Pin-Priority: 50'>>/etc/apt/preferences.d/kali.pref"
sudo apt update

#Entry for tools installed from kali repositories
sudo aptitude install -t kali-rolling wpscan #Wordpress Automated Vulnerability Scanner
#Using above method you can install any supported tool from kali's repositories as per your need :)


sudo apt-fast install -y apt-transport-https
sudo apt-fast install -y libcurl4-ssl-dev
sudo apt-fast install -y libssl-dev
sudo apt-fast install -y jq
sudo apt-fast install -y ruby-full
sudo apt-fast install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt-fast install -y build-essential libssl-dev libffi-dev python-dev
sudo apt-fast install -y python-setuptools
sudo apt-fast install -y libldns-dev
sudo apt-fast install -y python3
sudo apt-fast install -y python3-pip
sudo apt-fast install -y python-dnspython
sudo apt-fast install -y git gcc make libcap-dev
sudo apt-fast install -y npm
sudo apt-fast install -y nmap phantomjs
sudo apt-fast install -y gem
sudo apt-fast install -y perl
sudo apt-fast install -y parallel
sudo apt-fast install -y tmux
sudo apt-fast install -y dnsutils
pip3 install jsbeautifier
echo ""
} > /dev/null 2>&1

echo "${GREEN} [+] Setting bash_profile aliases ${RESET}"
curl --silent https://raw.githubusercontent.com/unethicalnoob/aliases/master/bashprofile > ~/.bash_profile
echo "${BLUE} If it doesn't work, set it manually ${RESET}"
echo ""

echo "${GREEN} [+] Installing Golang ${RESET}"
if [ ! -f /usr/bin/go ];then
    cd ~
    {
    wget -q -O - https://raw.githubusercontent.com/canha/golang-tools-install-script/master/goinstall.sh | bash
	export GOROOT=$HOME/.go
	export PATH=$GOROOT/bin:$PATH
	export GOPATH=$HOME/go
    echo 'export GOROOT=$HOME/.go' >> ~/.bash_profile
    echo 'export GOPATH=$HOME/go' >> ~/.bash_profile
    echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile
    source ~/.bash_profile
    } > /dev/null
else
    echo "${BLUE} Golang is already installed${RESET}"
fi
echo "${BLUE} Done installing Golang ${RESET}"
echo ""


echo "${GREEN} [+] Installing Subdomain Enum tools ${RESET}"
{
go get -u github.com/projectdiscovery/subfinder/cmd/subfinder
git clone https://github.com/Healdb/Elevate.git ~/tools/Elevate
go get -u github.com/harleo/knockknock
go get -u github.com/tomnomnom/assetfinder
sudo pip3 install spyse.py


crtsh(){
git clone https://github.com/YashGoti/crtsh.py ~/tools/crtsh.py
cd ~/tools/crtsh.py && sudo pip3 install -r requirements.txt
}
crtsh

shosubgo(){
git clone https://github.com/incogbyte/shosubgo.git ~/tools/shosubgo
cd ~/tools/shosubgo/
go build main.go && mv main shosubgo && sudo mv shosubgo /usr/bin/
}
shosubgo

sublister(){
git clone https://github.com/aboul3la/Sublist3r.git ~/tools/Sublist3r
cd ~/tools/Sublist3r
sudo pip3 install -r requirements.txt
}
sublister

findomain(){
cd ~/tools
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
sudo chmod +x findomain-linux
sudo mv findomain-linux /usr/bin/findomain
}
findomain

amass(){
go get -u -v github.com/OWASP/Amass/...
}
amass

} > /dev/null 2>&1
echo "${BLUE} Done ${RESET}"
echo ""

echo "${GREEN} [+] Installing Resolvers ${RESET}"
{
pip3 install dnsgen
pip3 install py-altdns
pip3 install aiodnsbrute
go get -u github.com/projectdiscovery/shuffledns/cmd/shuffledns
go get -u github.com/tomnomnom/httprobe
go get -u github.com/projectdiscovery/dnsprobe
go get -u github.com/tomnomnom/burl
curl --silent https://raw.githubusercontent.com/rastating/dnmasscan/master/dnmasscan > dnmasscan && sudo mv dnmasscan /usr/bin/
go get -u github.com/projectdiscovery/httpx/cmd/httpx


massdns(){
git clone https://github.com/blechschmidt/massdns.git ~/tools/massdns
cd ~/tools/massdns
make
}
massdns

knockpy(){
git clone https://github.com/guelfoweb/knock.git ~/tools/knockpy
cd ~/tools/knockpy
sudo python setup.py install
}
knockpy
} > /dev/null 2>&1
echo "${BLUE} Done ${RESET}"
echo ""

echo "${GREEN} [+] Installing Cloud workflow Tools ${RESET}"
{
gem install aws_recon
sudo pip3 install awscli --upgrade --user
git clone https://github.com/gwen001/s3-buckets-finder.git ~/tools/s3-buckets-finder
git clone https://github.com/nahamsec/lazys3.git ~/tools/lazys3
git clone https://github.com/ghostlulzhacks/s3brute.git ~/tools/s3brute
git clone https://github.com/greycatz/CloudUnflare.git ~/tools/CloudUnflare
git clone https://github.com/fellchase/flumberboozle ~/tools/flumberboozle
git clone https://github.com/appsecco/spaces-finder.git ~/tools/spaces-finder
pip3 install festin

cloudflair(){
git clone https://github.com/christophetd/CloudFlair.git ~/tools/CloudFlair
cd ~/tools/CloudFlair && chmod +x cloudflair.py
sudo pip3 install -r requirements.txt
}
cloudflair

echo "${GREEN} [+] Installing Fuzzing tools ${RESET}"
{
go get -u github.com/OJ/gobuster
go get -u github.com/ffuf/ffuf
git clone https://github.com/maurosoria/dirsearch.git ~/tools/dirsearch
sudo apt-fast install wfuzz
go get -u github.com/tomnomnom/meg
go get -u github.com/tomnomnom/waybackurls
sudo pip3 install dirhunt
sudo apt-fast install -y dirb
go get -u github.com/lc/gau

secretfinder(){
git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
cd ~/tools/SecretFinder && chmod +x secretfinder
sudo pip3 install -r requirements.txt
}
secretfinder
} > /dev/null 2>&1
echo "${BLUE} Done ${RESET}"
echo ""


echo "${GREEN} [+] Content Discovery tools ${RESET}"
{
go get -u github.com/jaeles-project/gospider
pip3 install scrapy
go get -u github.com/m4ll0k/Aron
git clone https://github.com/s0md3v/Arjun.git ~/tools/Arjun

paramspider(){
git clone https://github.com/devanshbatham/ParamSpider ~/tools/ParamSpider
cd ~/tools/ParamSpider
sudo pip3 install -r requirements.txt
}
paramspider

hakrawler(){
git clone https://github.com/hakluke/hakrawler.git ~/tools/hakrawler
cd ~/tools/hakrawler
go build main.go && mv main hakrawler
sudo mv hakrawler /usr/bin/
}
hakrawler
} > /dev/null 2>&1
echo "${BLUE} Done ${RESET}"
echo ""

echo "${GREEN} [+] Installing CMS Tools ${RESET}"
{
git clone https://github.com/rezasp/joomscan.git ~/tools/CMS/Joomscan
sudo gem install wpscan
git clone https://github.com/0ang3el/aem-hacker.git ~/tools/CMS/aem-hacker
sudo pip3 install droopescan

CMSmap(){
git clone https://github.com/Dionach/CMSmap.git ~/tools/CMS/CMSmap
cd ~/tools/CMS/CMSmap
sudo pip3 install .
}
CMSmap

wig(){
git clone https://github.com/jekyc/wig.git ~/tools/CMS/wig
cd ~/tools/wig
sudo python3 setup.py install
}
wig

CMSeeK(){
git clone https://github.com/Tuhinshubhra/CMSeeK.git ~/tools/CMS/CMSeeK
cd ~/tools/CMS/CMSeek
sudo python3 -m pip install -r requirements.txt
}
CMSeeK


drupwn(){
git clone https://github.com/immunIT/drupwn.git ~/tools/CMS/drupwn
cd ~/tools/CMS/drupwn
sudo python3 setup.py install
}
drupwn
} > /dev/null 2>&1
echo "${BLUE} Done ${RESET}"
echo ""


echo "${GREEN} [+] Downloading Git tools ${RESET}"
{
go get -u github.com/eth0izzle/shhgit
pip3 install truffleHog

echo "${GREEN} [+] Fingerprinting & CVE tools ${RESET}"
{
sudo pip3 install webtech
go get -u github.com/projectdiscovery/chaos-client/cmd/chaos
go get -u github.com/projectdiscovery/nuclei/cmd/nuclei
git clone https://github.com/projectdiscovery/nuclei-templates ~/tools/nuclei-templates
go get -u github.com/tomnomnom/gf

gfp(){
cd ~/tools
git clone https://github.com/1ndianl33t/Gf-Patterns
mv ~/tools/Gf-Patterns/*.json /root/.gf
rm -rf ~/tools/Gf-Patterns
wget https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json;
mv ~/tools/potential.json /root/.gf;
echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc;
cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf;
}
gfp

waf(){
git clone https://github.com/EnableSecurity/wafw00f.git ~/tools/waff00f
cd ~/tools/wafw00f
sudo python3 setup.py install
}
waf
} > /dev/null 2>&1
echo "${BLUE} Done ${RESET}"
echo ""

echo "${GREEN} [+] Network and Port Scanning tools ${RESET}"
{
sudo apt-fast install -y nmap
sudo apt-fast install -y brutespray
sudo apt-fast install -y nikto
sudo apt-fast install -y masscan
go get -u github.com/j3ssie/metabigor
go get -u github.com/projectdiscovery/naabu/cmd/naabu


asnlookup(){
git clone https://github.com/yassineaboukir/asnlookup.git ~/tools/asnlookup
cd ~/tools/asnlookup
sudo pip3 install -r requirements.txt
}
} > /dev/null 2>&1
echo "${BLUE} Done ${RESET}"
echo ""

echo "${GREEN} [+] Downloading wordlists ${RESET}"
{
git clone https://github.com/assetnote/commonspeak2-wordlists ~/wordlists/commonspeak2-wordlists
cd ~/tools/wordlists/ && wget https://raw.githubusercontent.com/Mad-robot/recon-tools/master/dicc.txt
git clone https://github.com/1N3/IntruderPayloads ~/wordlists/IntruderPayloads
git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/wordlists/PayloadsAllTheThings
git clone https://github.com/danielmiessler/SecLists ~/wordlists/SecLists
cd ~/wordlists/SecLists/Discovery/DNS/
##THIS FILE BREAKS MASSDNS AND NEEDS TO BE CLEANED
cat dns-Jhaddix.txt | head -n -14 > clean-jhaddix-dns.txt
} > /dev/null 2>&1
printf "${BLUE} Done ${RESET}"
echo ""
echo ""

echo "${GREEN} [+] Installing tomnomnom tools ${RESET}"
echo "${GREEN} check out his other tools as well  ${RESET}"
{
go get -u github.com/tomnomnom/hacks/concurl
go get -u github.com/tomnomnom/unfurl
go get -u github.com/tomnomnom/hacks/anti-burl
go get -u github.com/tomnomnom/hacks/filter-resolved
go get -u github.com/tomnomnom/fff
go get -u github.com/tomnomnom/qsreplace
} > /dev/null 2>&1
echo "${BLUE} Done ${RESET}"
echo ""

echo "${GREEN} [+] Installing Miscellaneous tools ${RESET}"
{
git clone https://github.com/lijiejie/ds_store_exp/ ~/tools/ds_store_exp
} > /dev/null 2>&1

echo "${RED} use the command 'source ~/.bash_profile' for the shell functions to work ${RESET}"
echo ""
echo "${RED}      ALL THE THANKS TO THE BEST PEOPLE OF THE INFOSEC COMMUNITY   ${RESET}"
