# BUGBOUNTY

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

```

### HERRAMIENTAS
```
``
## OSINT
``

Maltegos
SpiderFoot
Google Dorks
``
## ENUMERACIÓN SUBDOMINIOS
 ``
Subfinder

``
## FILTRADO
 ``
HTTPX
``
## CONTENT DISCOVERY
 ``
FFUF
Gobuster
FeroxBuster
Dirsearch
Scavenger (BurpSuite extension)
GAU
Waymore
``
## CONTENT DISCOVERY MOBILE
 ``
APKLeaks

``
``
## CRAWLING

Katana
 ``
### ANALISIS VULNERABILIDADES
 ```
OWAS ZAP
Burp Suite
Nuclei ---> nuclei -l subdomainNasa -s critical,high,medium,low -as -ss -template-spray -concurrency 10 -bulk-size 200 -o sanNasa -p socks4:127.0.0.1:9050
 -as: checkea dominios
 -template-spray: aplica multiples plantillas
 -p socks4://127.0.0.1:9050  --> utiliza el proxy tor para que no te baneen la ip (mirar consulta chatgpt para ver como configurarlo)
 -rl : para ir mas despacio
SQLMAP
Jsqlinjection (sqli visual)
``
## CMS VULNERABILITIES
 ``
-WPScan (wordpress)
-Drooperscan (droopal)
```
## JAVASCRIPT PARSING
 ``
GAP (BurpSuite extension)

Command line spidering --->
 - xnLinkFinder ---> python3 xnLinkFinder.py -i tesla.com -v -d 2 -sp https://tesla.com
```

### FASES AUTOMATIZADAS
 ```

``
## RECON SUBDOMINIOS
subfinder -d nasa.gov | .o subdomainsNasa
 ``
``
## DETECTAR STACKS
``
nuclei -t tech-detect.yaml -l subdomainsNasa
``
## CRAWLING (DETECTAR ENDPOINTS, DIRECTORIOS, RECURSOS)
``
katana -list subdomainsNasa -c 20
``
## COMBINACION FASES ANTERIORES (web debiles)
``
subfinder -d vulnhub.com | httpx -mc 200 | katana | nuclei -dast
``
## DETECCION DE VULNERABILIDADES
nuclei -l subdomainNasa -s critical,high,medium,low -as -ss -template-spray -concurrency 10 -bulk-size 200 -o sanNasa -p socks4:127.0.0.1:9050
 -as: checkea dominios y detecta la tecnologia
 -template-spray: aplica multiples plantillas
 -p socks4://127.0.0.1:9050  --> utiliza el proxy tor para que no te baneen la ip (mirar consulta chatgpt para ver como configurarlo)
 -rl : para ir mas despacio
``
``
## CRAWLING FICHEROS .JS
``
cat subdomainsNasa | katana | grep -e js | httpx -mc 200 >> JSFiles.txt
``
## ANALISIS FICHEROS JS
``
nuclei -i JSFiles.txt -tags token,exposure
``

