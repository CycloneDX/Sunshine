```
 ▗▄▄▖▗▖ ▗▖▗▖  ▗▖ ▗▄▄▖▗▖ ▗▖▗▄▄▄▖▗▖  ▗▖▗▄▄▄▖
▐▌   ▐▌ ▐▌▐▛▚▖▐▌▐▌   ▐▌ ▐▌  █  ▐▛▚▖▐▌▐▌   
 ▝▀▚▖▐▌ ▐▌▐▌ ▝▜▌ ▝▀▚▖▐▛▀▜▌  █  ▐▌ ▝▜▌▐▛▀▀▘
▗▄▄▞▘▝▚▄▞▘▐▌  ▐▌▗▄▄▞▘▐▌ ▐▌▗▄█▄▖▐▌  ▐▌▐▙▄▄▖
```
  
Sunshine: actionable CycloneDX visualization tool. 
<br><br>
It takes a JSON CycloneDX file as input and provides as output an HTML containing a chart and a table representation of the components, dependencies, vulnerabilities and licenses. [See a sample HTML output here.](https://lucacapacci.github.io/Sunshine/sample.html)

<br>

Can be used in 2 ways:
- As a web application: all submitted data is processed locally within your browser, without being transmitted anywhere else.
- As a standalone CLI tool.
<br>

Usage of the web application:
- option 1: via the online version at URL https://lucacapacci.github.io/Sunshine/
- option 2: by running `python3 -m http.server 8000` and opening a browser at URL http://127.0.0.1:8000

<br>
Usage of the CLI version:

```
sunshine.py [-h] [-v] [-i INPUT] [-o OUTPUT]

options:
  -h, --help           show this help message and exit
  -v, --version        show program version
  -i, --input INPUT    path of input CycloneDX file
  -o, --output OUTPUT  path of output HTML file
```

<br>

Credits:
- made by: [Luca Capacci](https://www.linkedin.com/in/lucacapacci/)
- contributor: [Mattia Fierro](https://www.linkedin.com/in/mattiafierro/)
