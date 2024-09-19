# BUGBOUNTY

### HERRAMIENTAS
```

OSINT

-Maltegos
-SpiderFoot
-Google Dorks

ENUMERACIÓN SUBDOMINIOS

-Subfinder

FILTRADO

-HTTPX

CONTENT DISCOVERY
 
-FFUF
-Gobuster
-FeroxBuster
-Dirsearch
-Scavenger (BurpSuite extension)
-GAU
-Waymore

CONTENT DISCOVERY MOBILE

-APKLeaks

 CRAWLING

-Katana
 ```
### ANALISIS VULNERABILIDADES
 ```
-OWAS ZAP
-Burp Suite
-Nuclei ---> nuclei -l subdomainNasa -s critical,high,medium,low -as -ss -template-spray -concurrency 10 -bulk-size 200 -o sanNasa -p socks4:127.0.0.1:9050
 -as: checkea dominios
 -template-spray: aplica multiples plantillas
 -p socks4://127.0.0.1:9050  --> utiliza el proxy tor para que no te baneen la ip (mirar consulta chatgpt para ver como configurarlo)
 -rl : para ir mas despacio
-SQLMAP
-Jsqlinjection (sqli visual)

 CMS VULNERABILITIES

-WPScan (wordpress)
-Drooperscan (droopal)
```
### JAVASCRIPT PARSING
```
-GAP (BurpSuite extension)

Command line spidering --->
xnLinkFinder ---> python3 xnLinkFinder.py -i tesla.com -v -d 2 -sp https://tesla.com

```
### FASES AUTOMATIZADAS
 ```

RECON SUBDOMINIOS
subfinder -d nasa.gov | .o subdomainsNasa

ETECTAR STACKS
nuclei -t tech-detect.yaml -l subdomainsNasa

CRAWLING (DETECTAR ENDPOINTS, DIRECTORIOS, RECURSOS)
katana -list subdomainsNasa -c 20

COMBINACION FASES ANTERIORES (web debiles)
subfinder -d vulnhub.com | httpx -mc 200 | katana | nuclei -dast

DETECCION DE VULNERABILIDADES
nuclei -l subdomainNasa -s critical,high,medium,low -as -ss -template-spray -concurrency 10 -bulk-size 200 -o sanNasa -p socks4:127.0.0.1:9050
 -as: checkea dominios y detecta la tecnologia
 -template-spray: aplica multiples plantillas
 -p socks4://127.0.0.1:9050  --> utiliza el proxy tor para que no te baneen la ip (mirar consulta chatgpt para ver como configurarlo)
 -rl : para ir mas despacio

CRAWLING FICHEROS .JS
cat subdomainsNasa | katana | grep -e js | httpx -mc 200 >> JSFiles.txt

ANALISIS FICHEROS JS
nuclei -i JSFiles.txt -tags token,exposure

```
### ONELINER
```

1. Subdomain Enumeration with Subfinder 
2. Probing with HTTPX 
3. URL Collection with GAU and WaybackURLs 
4. Extracting Interesting URLs 
5. Checking for Alive URLs with 200 Status Code 
6. Full Port Scan with Nmap 
7. Vulnerability Scanning with Nuclei
8. Directory Fuzzing with FFUF


subfinder -d example.com | tee subdomains.txt | \
xargs -I{} -P10 sh -c '
  echo "Scanning {}" && \
  httpx -silent -title -tech-detect -status-code -location -ip -cname -cdn -follow-redirects -timeout 30 -retries 2 -t 100 -threads 50 -random-agent -u "{}" | tee -a httpx_results.txt && \
  gau "{}" | tee -a gau_urls.txt && \
  waybackurls "{}" | tee -a waybackurls.txt && \
  cat gau_urls.txt waybackurls.txt | sort -u | grep -E "\.js$|\.php$|\.aspx$|\.jsp$|\.json$" | tee -a interesting_urls.txt && \
  cat gau_urls.txt waybackurls.txt | sort -u | \
  xargs -I{} sh -c "curl -s -o /dev/null -w \"%{http_code} %{url_effective}\\n\" {} | grep '^200' | tee -a alive_200_urls.txt" && \
  nmap -p- --open -T4 -Pn -v -oN nmap/{}_full_scan.txt "{}" && \
  nuclei -l subdomains.txt -t cves/ -o nuclei_vulnerabilities.txt && \
  ffuf -u "{}/FUZZ" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200 -o ffuf_results.txt

```
### IF ONELINER ERROR
```
this error
xargs: command line cannot be assembled, too long

do this.
Step 1: Run subfinder and save the subdomains

subfinder -d example.com | tee subdomains.txt

Step 2: Process each subdomain individually

while read -r subdomain; do
  echo "Scanning $subdomain"

  # Run httpx
  httpx -silent -title -tech-detect -status-code -location -ip -cname -cdn -follow-redirects \
    -timeout 30 -retries 2 -t 100 -threads 50 -random-agent -u "$subdomain" | tee -a httpx_results.txt

  # Run gau and waybackurls
  gau "$subdomain" | tee -a gau_urls.txt
  waybackurls "$subdomain" | tee -a waybackurls.txt

  # Extract interesting URLs
  cat gau_urls.txt waybackurls.txt | sort -u | grep -E "\.js$|\.php$|\.aspx$|\.jsp$|\.json$" | tee -a interesting_urls.txt

  # Check for alive URLs
  cat gau_urls.txt waybackurls.txt | sort -u | xargs -I{} sh -c \
    'curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" {} | grep "^200" | tee -a alive_200_urls.txt'

  # Run nmap
  nmap -p- --open -T4 -Pn -v -oN nmap/"${subdomain}_full_scan.txt" "$subdomain"

  # Run nuclei
  nuclei -l subdomains.txt -t cves/ -o nuclei_vulnerabilities.txt

  # Run ffuf
  ffuf -u "$subdomain/FUZZ" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200 -o ffuf_results.txt

```
### HIDDEN JS PARAMETER DISCOVERY
```
#!/bin/bash

cat subs.txt | (gau --threads 20 --blacklist jpg,jpeg,gif,png,tiff,ttf,otf,woff,woff2,ico,svg,pdf,txt,mp4,avi,mov,mkv,exe,zip,tar,gz,rar,7z || hakrawler -depth 5 -plain -insecure || waybackurls || katana -d 5 --js-crawl --auto-redirect --extensions js,json,php,aspx,asp,jsp,html,htm --proxy http://127.0.0.1:8080) | sort -u | httpx -silent -threads 200 -status-code -title -tech-detect -content-length -server | tee -a httpx_full.txt | grep -Eiv '\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt|pdf|mp4|avi|mov|mkv|exe|zip|tar|gz|rar|7z|css|doc|docx|xls|xlsx|ppt|pptx)$' | while read url; do vars=$(curl -sL $url | grep -Eo "(var |let |const |function |class |import |export )[a-zA-Z0-9_]+" | sed -e 's, , '"$url"':,' -e 's/\(var \|let \|const \|function \|class \|import \|export \)//g' | grep -Eiv '\.js$|\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+$' | sed 's/$/=FUZZ/'); echo -e "\e[1;33m$url\e[1;32m$vars"; done | tee -a js_parameters.txt

```
### SQLMAP COMMAND
```
sqlmap -u "https://target.com" --crawl=3 --level=5 --risk=3 --tamper="apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,commalesslimit,commalessmid,commentbeforeparentheses,concat2concatws,equaltolike,escapequotes,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,overlongutf8,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,varnish,versionedkeywords,versionedmorekeywords,xforwardedfor" --dbs --random-agent --batch --threads=10 --output-dir=InjectionResult --time-sec=10 --retries=3 --flush-session --fresh-queries -v 3
```
### ENLACES INTERES
```
Https://bit.ly/3clYgdt --> secrets of automation - kings in bug bounty

https://wordlists.assetnote.io/ --> all wordlists

GitHub.com/0xDexter0us/Scavenger --> content discovery list custom BurpSuite extension

Visualping/bbradar.io --> notifica por correo cuando sale un nuevo programa de bug bounty en cualquier plataforma

Firebounty ---> buscador de programas BugBounty por tipos

Waymore ---> https://github.com/xnl-h4ck3r/waymore ---> es la herramienta gau actualizada para content discovery

APKLeaks ---> github.com/dwisiswant0/apkleaks ---> mobile content discovery

ChangeDetection ---> github.com/dgtlmoon/changedetection.io ---> informa sobre nuevas features de la applicacion 

GAP ---> https://github.com/xnl-h4ck3r/burp-extensions ---> Extension de burpsuite para java script parsing

Hacksplaining ---> te explica las vulnerabilidades en una pagina real

https://www.bugbountyhunting.com/  ---> google de bug bounty --> reportes, write ups, payloads

https://nored0x.github.io/penetration%20testing/writeups-Bug-Bounty-hackrone/ ---> write ups de hackerone

https://writeups.io/ ---> write ups

https://chaos.projectdiscovery.io/#/ ---> Recon data for Public Bug Bounty Programs

https://github.com/KathanP19/HowToHunt ---> bug bounty guides

```
