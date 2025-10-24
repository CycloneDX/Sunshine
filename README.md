```
  ░██████   ░██     ░██ ░███    ░██   ░██████   ░██     ░██ ░██████░███    ░██ ░███████ 
░██         ░██     ░██ ░██░██  ░██ ░██         ░██     ░██   ░██  ░██░██  ░██ ░██        
 ░████████  ░██     ░██ ░██ ░██ ░██  ░████████  ░██████████   ░██  ░██ ░██ ░██ ░██████  
        ░██ ░██     ░██ ░██  ░██░██         ░██ ░██     ░██   ░██  ░██  ░██░██ ░██             
  ░██████     ░██████   ░██    ░███   ░██████   ░██     ░██ ░██████░██    ░███ ░███████
```
  
Sunshine: actionable CycloneDX visualization tool. 
<br><br>
It takes a JSON CycloneDX file as input and provides as output an HTML containing a chart and table representation of the components, dependencies, vulnerabilities and licenses. It can also enrich data by adding EPSS and CISA KEV information. See a sample HTML output [here without enriched data](https://cyclonedx.github.io/Sunshine/sample.html) and [here with enriched data](https://cyclonedx.github.io/Sunshine/sample_enriched.html).

<br>

Can be used in 2 ways:
- As a web application: all submitted data is processed locally within your browser, without being transmitted anywhere else.
- As a standalone CLI tool.
<br>

Usage of the web application:
- option 1: via the online version at URL https://cyclonedx.github.io/Sunshine/
- option 2: by running `python3 -m http.server 8000` and opening a browser at URL http://127.0.0.1:8000

<br>
Usage of the CLI version:

```
# Installing dependencies
pip3 install -r requirements.txt

# Basic usage without data enrichment
python sunshine.py -i your-input.json -o your-output.html

# Basic usage with EPSS and CISA KEV data enrichment
python sunshine.py -i your-input.json -o your-output.html -e

# All options
sunshine.py [-h] [-i INPUT] [-o OUTPUT] [-e] [-k] [-cs] [-hs] [-ms] [-ls] [-c MIN_CVSS] [-p MIN_EPSS] [-n]
options:
  -h, --help                              show this help message and exit
  -i, --input INPUT                       path of input CycloneDX file
  -o, --output OUTPUT                     path of output HTML file
  -e, --enrich                            enrich CVEs with EPSS and CISA KEV
  -k, --only-in-cisa-kev                  show only vulnerabilities in CISA KEV
  -cs, --only-critical-severity           show only vulnerabilities with critical severity
  -hs, --only-high-severity-or-above      show only vulnerabilities with high severity or above
  -ms, --only-medium-severity-or-above    show only vulnerabilities with medium severity or above
  -ls, --only-low-severity-or-above       show only vulnerabilities with low severity or above
  -c, --min-cvss MIN_CVSS                 show only vulnerabilities with score equal to or greater than the selected value, which can be in rage 0.0-10.0
  -p, --min-epss MIN_EPSS                 show only vulnerabilities with EPSS equal to or greater than the selected value, which can be in rage 0.00-1.00
  -n, --no-segment-limit                  prevent the automatic conversion of charts with many segments into still images
```

<br>

Credits:
- made by: [Luca Capacci](https://www.linkedin.com/in/lucacapacci/)
- contributor: [Mattia Fierro](https://www.linkedin.com/in/mattiafierro/)
