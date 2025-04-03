# This file is part of CycloneDX Sunshine
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


__all__ = [
  # This module does not export any symbols; all sumbols are private/internal.
]

import json
import argparse
import os
import html
import copy

VERSION = "0.9"
NAME = "Sunshine"

PREFERRED_VULNERABILITY_RATING_METHODS_ORDER = ["CVSSv4",
                                                "CVSSv31",
                                                "CVSSv3",
                                                "CVSSv2",
                                                "OWASP",
                                                "SSVC",
                                                "other"]

VALID_SEVERITIES = {"critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1,
                    "info": 0,
                    "information": 0,
                    "clean": -1}

GREY = '#bcbcbc'
GREEN = '#7dd491'
YELLOW = '#fccd58'
ORANGE = '#ff9335'
RED = '#ff4633'
DARK_RED = '#a10a0a'
LIGHT_BLUE = '#9fc5e8'

BASIC_STYLE = { "color": GREY, "borderWidth": 2 }
INFORMATION_STYLE = { "color": GREEN, "borderWidth": 2 }
LOW_STYLE = { "color": YELLOW, "borderWidth": 2 }
MEDIUM_STYLE = { "color": ORANGE, "borderWidth": 2 }
HIGH_STYLE = { "color": RED, "borderWidth": 2 }
CRITICAL_STYLE = { "color": DARK_RED, "borderWidth": 2 }
TRANSITIVE_VULN_STYLE = { "color": LIGHT_BLUE, "borderWidth": 2 }


STYLES = {"critical": CRITICAL_STYLE,
          "high": HIGH_STYLE,
          "medium": MEDIUM_STYLE,
          "low": LOW_STYLE,
          "information": INFORMATION_STYLE,
          "clean": BASIC_STYLE}


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sunshine - SBOM visualization tool</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
    <script src="https://code.jquery.com/jquery-3.7.1.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.8/pdfmake.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.8/vfs_fonts.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

    <script src="https://fastly.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js"></script>
    <style>
        body {
            margin: 20px;
            height: 100vh;
            background: linear-gradient(to right, #032c57, #1C538E);
        }
        #output {
            white-space: pre-line;
            background-color: #ffffff;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-top: 10px;
            font-family: "Courier New", "Lucida Console", monospace;
        }

        #chart-container {
            background-color: #ffffff;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            position: relative;
        }

        #chart-container-inner, #chart-container-only-vulnerable-inner {
            background-color: #ffffff;
            padding: 10px;
            position: relative;
            height: 90vh;
            overflow: hidden;
        }
        #chart-container-placeholder {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        #table-container, #info-table-container, #vulnerabilities-table-container {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        #table-container-placeholder, #info-table-container-placeholder, #vulnerabilities-table-container-placeholder {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        #upload-file-container {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        #file-input {
            margin: 20px;
        }

        .dataTables_filter {
            display: none;
        }
        th input {
            width: 100%;
            box-sizing: border-box;
        }

        .dataTables_length {
            padding-bottom: 10px !important;
        }
        .light-text {
            color: #baccde;
        }

        .dt-buttons {
            float: right;
        }
        .active>.page-link, .page-link.active {
            background-color: #1C538E !important;
            color: white !important;
        }

        .page-link {
            color: #1C538E;
        }

        #components-table_paginate, #vulnerabilities-table_paginate {
            float: right;
            margin-top: -33px;
        }

        .bg-dark-red {
            background-color: #a10a0a;
            color: white;
        }

        .bg-orange {
            background-color: #ff9335;
            color: white;
        }

        .bg-yellow {
            background-color: #fccd58;
            color: white;
        }

        .bg-light-blue {
            background-color: #9fc5e8;
            color: black;
        }

        #footer {
            position: fixed;
            bottom: 0;
            left: 0;
            width: 100%;
            background-color: #032c57;
            color: #baccde;
            text-align: center;
            z-index: 100000;
        }

        #footer a {
            color: #baccde;
        }

        #info-table_paginate, #info-table_length, #info-table_info {
            display: none;
        }

        .opaque {
            opacity: 0.5;
        }

        @media print {
            body {
                background-color: transparent !important;
                background-image: none !important;
            }
        }
    
    </style>
</head>


<body>
    <h1 class="light-text">Sunshine - SBOM visualization tool</h1>
    <br>
    <div id="upload-file-container">
        <span>Analyzed CycloneDX JSON file: <i><FILE_NAME_HERE></i></span>
    </div>

    <br>
    <h3 class="light-text">Summary</h3>
    <div id="info-table-container">
        <table id="info-table" class="table table-striped table-bordered" style="width:100%"><METADATA_TABLE_HERE></table>
    </div>

    <br><br>
    <h3  class="light-text">Components chart</h3>
    <div id="chart-container">
    This chart visualizes components and their dependencies, with each segment representing a single component. The chart provides a hierarchical view of the dependency structure, with relationships radiating outward from the core components.<br>
    <ul>
        <li><b>Innermost circle:</b> represents components that are independent and not dependencies for any other components.</li>
        <li><b>Outer circles:</b> each segment represents a dependency of the corresponding segment in the circle immediately inside it. The farther a segment is from the center, the deeper the dependency level.</li>
    </ul>
    <i>Note: If there is only one circle, it means that no dependency relationships are defined in the input file.</i>
    <br><br>
    The colors of the segments indicate the vulnerability status of the components:
    <ul>
        <li><b>Dark red:</b> affected by at least one critical severity vulnerability.</li>
        <li><b>Red:</b> affected by at least one high severity vulnerability.</li>
        <li><b>Orange:</b> affected by at least one medium severity vulnerability.</li>  
        <li><b>Yellow:</b> affected by at least one low severity vulnerability.</li>  
        <li><b>Green:</b> affected by at least one informational severity vulnerability.</li>  
        <li><b>Light blue:</b> not directly affected by vulnerabilities but has at least one vulnerable dependency.</li>  
        <li><b>Grey:</b> neither the component nor its dependencies are affected by any vulnerabilities.</li>
    </ul>
    The chart is interactive:  
    <ul>
        <li><b>Hovering:</b> displays details about a component, including its name, version, and list of vulnerabilities.</li>
        <li><b>Clicking:</b> refocuses the chart. The clicked segment becomes the center (second innermost circle), showing only that component and its dependencies. In this view, the innermost circle is always blue. Clicking the blue circle navigates back up one level in the dependency hierarchy.</li>
    </ul>
    <hr>
    <div class="form-check">
      <input class="form-check-input" type="radio" name="showComponentsSwitch" id="allComponents" value="allComponents" checked onchange="handleShowComponentsSwitchChange(this)">
      <label class="form-check-label" for="allComponents">
        Show all components
      </label>
    </div>
    <div class="form-check">
      <input class="form-check-input" type="radio" name="showComponentsSwitch" id="vulnerableComponents" value="vulnerableComponents" onchange="handleShowComponentsSwitchChange(this)">
      <label class="form-check-label" for="vulnerableComponents">
        Show only components with direct or transitive vulnerabilities
      </label>
    </div>
    <hr>
    <div id="chart-container-inner" style="display: block"></div>
    <div id="chart-container-only-vulnerable-inner" style="display: none"></div>
    </div>
    <br>
    <h3  class="light-text">Components table</h3>
    <div id="table-container">
        This table visualizes components, their dependencies, vulnerabilities and licenses.<br>
        The colors of the elements in columns "Component", "Depends on" and "Dependency of" indicate the vulnerability status of the components:
        <ul>
            <li><b>Dark red:</b> affected by at least one critical severity vulnerability.</li>
            <li><b>Red:</b> affected by at least one high severity vulnerability.</li>
            <li><b>Orange:</b> affected by at least one medium severity vulnerability.</li>  
            <li><b>Yellow:</b> affected by at least one low severity vulnerability.</li>  
            <li><b>Green:</b> affected by at least one informational severity vulnerability.</li>  
            <li><b>Light blue:</b> not directly affected by vulnerabilities but has at least one vulnerable dependency.</li>  
            <li><b>Grey:</b> neither the component nor its dependencies are affected by any vulnerabilities.</li>
        </ul>
        <br>
        The colors of the elements in columns "Direct vulnerabilities" and "Transitive vulnerabilities" indicate the severity of the vulnerabilities:
        <ul>
            <li><b>Dark red:</b> critical.</li>
            <li><b>Red:</b> high.</li>
            <li><b>Orange:</b> medium.</li>  
            <li><b>Yellow:</b>low.</li>  
            <li><b>Green:</b>informational.</li> 
        </ul>
        <hr><br>
            <div id="table-container-inner">
                <table id="components-table" class="table table-striped table-bordered" style="width:100%"><COMPONENTS_TABLE_HERE></table>
            </div>
    </div>
    <br>
    <h3 class="light-text">Vulnerabilities table</h3>
    <div id="vulnerabilities-table-container">
        This table focuses on vulnerabilities and shows the components that are affected either directly or transitively.<br>
        The colors of the elements in column "Vulnerability" indicate the severity of the vulnerabilities:
        <ul>
            <li><b>Dark red:</b> critical.</li>
            <li><b>Red:</b> high.</li>
            <li><b>Orange:</b> medium.</li>  
            <li><b>Yellow:</b>low.</li>  
            <li><b>Green:</b>informational.</li> 
        </ul>
        <br>
        The colors of the elements in columns "Directly vulnerable components" and "Transitively vulnerable components" indicate the vulnerability status of the components:
        <ul>
            <li><b>Dark red:</b> affected by at least one critical severity vulnerability.</li>
            <li><b>Red:</b> affected by at least one high severity vulnerability.</li>
            <li><b>Orange:</b> affected by at least one medium severity vulnerability.</li>  
            <li><b>Yellow:</b> affected by at least one low severity vulnerability.</li>  
            <li><b>Green:</b> affected by at least one informational severity vulnerability.</li>  
            <li><b>Light blue:</b> not directly affected by vulnerabilities but has at least one vulnerable dependency.</li> 
        </ul>
        <hr><br>
                <table id="vulnerabilities-table" class="table table-striped table-bordered" style="width:100%"><VULNERABILITIES_TABLE_HERE></table>
    </div>
    <script type="text/javascript">
        function showDiv(divId) {
            var div = document.getElementById(divId);
            if (div.style.display === "none") {
                div.style.display = "block";
            }
        }

        function hideDiv(divId) {
            var div = document.getElementById(divId);
            if (div.style.display === "block") {
                div.style.display = "none";
            }
        }

        function handleShowComponentsSwitchChange(radio) {
            if (radio.value == "allComponents") {
                hideDiv("chart-container-only-vulnerable-inner");
                showDiv("chart-container-inner");
                var shownChart = echarts.getInstanceByDom(document.getElementById("chart-container-inner"));
                shownChart.resize();
            }
            else if (radio.value == "vulnerableComponents") {
                hideDiv("chart-container-inner");
                showDiv("chart-container-only-vulnerable-inner");
                var shownChart = echarts.getInstanceByDom(document.getElementById("chart-container-only-vulnerable-inner"));
                shownChart.resize();
            }
        }

        var dom = document.getElementById('chart-container-inner');
        var myChart = echarts.init(dom, null, {
          renderer: 'canvas',
          useDirtyRect: false
        });
        var app = {};

        var option;

        const data = <CHART_DATA_HERE>;

        option = {
          tooltip: {
                formatter: function(params) {
                    return `${params.name}`;
                },
            },
          series: {
            radius: ['15%', '100%'],
            type: 'sunburst',
            sort: undefined,
            emphasis: {
              focus: 'ancestor'
            },
            data: data,
            label: {
              rotate: 'radial',
              show: false
            },
            levels: []
          }
        };

        if (option && typeof option === 'object') {
          myChart.setOption(option);
        }

        window.addEventListener('resize', myChart.resize);

        var domVuln = document.getElementById('chart-container-only-vulnerable-inner');
        var myChartVuln = echarts.init(domVuln, null, {
          renderer: 'canvas',
          useDirtyRect: false
        });

        var optionVuln;

        const dataVuln = <CHART_DATA_VULN_HERE>;

        optionVuln = {
          tooltip: {
                formatter: function(params) {
                    return `${params.name}`;
                },
            },
          series: {
            radius: ['15%', '100%'],
            type: 'sunburst',
            sort: undefined,
            emphasis: {
              focus: 'ancestor'
            },
            data: dataVuln,
            label: {
              rotate: 'radial',
              show: false
            },
            levels: []
          }
        };

        if (optionVuln && typeof optionVuln === 'object') {
          myChartVuln.setOption(optionVuln);
        }

        window.addEventListener('resize', myChartVuln.resize);

        let table = $('#components-table').DataTable({
            "order": [[ 1, "asc" ]],
            pageLength: 10,
            dom: 'Blfrtip',
            lengthMenu: [
                [10, 25, 50, -1],
                [10, 25, 50, 'All']
            ],
            buttons: [
              { extend: 'copy', className: 'btn btn-dark mb-3 btn-sm' },
              { extend: 'csv', className: 'btn btn-secondary mb-3 btn-sm' },
              { extend: 'excel', className: 'btn btn-success mb-3 btn-sm' },
              { extend: 'print', className: 'btn btn-danger mb-3 btn-sm', 
                customize: function (win) {
                    $(win.document.body).css('font-size', '10pt');
                    $(win.document.body).find('table').addClass('compact').css('font-size', 'inherit');

                    // Add landscape mode
                    var css = '@page { size: landscape; }',
                        head = win.document.head || win.document.getElementsByTagName('head')[0],
                        style = win.document.createElement('style');

                    style.type = 'text/css';
                    style.media = 'print';

                    if (style.styleSheet) {
                        style.styleSheet.cssText = css;
                    } else {
                        style.appendChild(win.document.createTextNode(css));
                    }
                    head.appendChild(style);
                }
              }
            ],
            orderCellsTop: true,
            "autoWidth": true
          });

        $('#components-table thead input').on('keyup change', function () {
            let columnIndex = $(this).parent().index();
            table.column(columnIndex).search(this.value).draw();
        });

        let summaryTable = $('#info-table').DataTable({
            "order": [[ 1, "asc" ]],
            pageLength: 10,
            dom: 'Blfrtip',
            lengthMenu: [
                [10, 25, 50, -1],
                [10, 25, 50, 'All']
            ],
            buttons: [
              { extend: 'copy', className: 'btn btn-dark mb-3 btn-sm' },
              { extend: 'csv', className: 'btn btn-secondary mb-3 btn-sm' },
              { extend: 'excel', className: 'btn btn-success mb-3 btn-sm' },
              { extend: 'print', className: 'btn btn-danger mb-3 btn-sm', 
                customize: function (win) {
                    $(win.document.body).css('font-size', '10pt');
                    $(win.document.body).find('table').addClass('compact').css('font-size', 'inherit');

                    // Add landscape mode
                    var css = '@page { size: landscape; }',
                        head = win.document.head || win.document.getElementsByTagName('head')[0],
                        style = win.document.createElement('style');

                    style.type = 'text/css';
                    style.media = 'print';

                    if (style.styleSheet) {
                        style.styleSheet.cssText = css;
                    } else {
                        style.appendChild(win.document.createTextNode(css));
                    }
                    head.appendChild(style);
                }
              }
            ],
            orderCellsTop: true,
            "autoWidth": true
          });

          let vulnerabilitiesTable = $('#vulnerabilities-table').DataTable({
            "order": [[ 1, "asc" ]],
            pageLength: 10,
            dom: 'Blfrtip',
            lengthMenu: [
                [10, 25, 50, -1],
                [10, 25, 50, 'All']
            ],
            buttons: [
              { extend: 'copy', className: 'btn btn-dark mb-3 btn-sm' },
              { extend: 'csv', className: 'btn btn-secondary mb-3 btn-sm' },
              { extend: 'excel', className: 'btn btn-success mb-3 btn-sm' },
              { extend: 'print', className: 'btn btn-danger mb-3 btn-sm', 
                customize: function (win) {
                    $(win.document.body).css('font-size', '10pt');
                    $(win.document.body).find('table').addClass('compact').css('font-size', 'inherit');

                    // Add landscape mode
                    var css = '@page { size: landscape; }',
                        head = win.document.head || win.document.getElementsByTagName('head')[0],
                        style = win.document.createElement('style');

                    style.type = 'text/css';
                    style.media = 'print';

                    if (style.styleSheet) {
                        style.styleSheet.cssText = css;
                    } else {
                        style.appendChild(win.document.createTextNode(css));
                    }
                    head.appendChild(style);
                }
              }
            ],
            orderCellsTop: true,
            "autoWidth": true
          });

        $('#vulnerabilities-table thead input').on('keyup change', function () {
            let columnIndex = $(this).parent().index();
            vulnerabilitiesTable.column(columnIndex).search(this.value).draw();
        });
      </script>
      <br><br>
      <div id="footer">Sunshine - SBOM visualization tool by <a href="https://www.linkedin.com/in/lucacapacci/">Luca Capacci</a> | <a href="https://github.com/CycloneDX/Sunshine/">GitHub repository</a> | <a href="https://github.com/CycloneDX/Sunshine/blob/main/LICENSE">License</a></div>
    </body>
</html>
"""


def custom_print(text):
    if __name__ == "__web__":
        from js import writeToLog
        writeToLog(text)
    else:
        print(text)


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


def create_fake_component(bom_ref):
    return {"name": bom_ref,
            "version": "-",
            "type": "-",
            "license": set(),
            "depends_on": set(),
            "dependency_of": set(),
            "vulnerabilities": [],
            "transitive_vulnerabilities": [],
            "max_vulnerability_severity": "clean",
            "has_transitive_vulnerabilities": False,
            "visited": False}


def create_base_component(component):
    new_component = {"name": component["name"],
                     "version": component["version"] if "version" in component else "-",
                     "type": component["type"] if "type" in component else "-",
                     "license": parse_licenses(component),
                     "depends_on": set(),
                     "dependency_of": set(),
                     "vulnerabilities": [],
                     "transitive_vulnerabilities": [],
                     "max_vulnerability_severity": "clean",
                     "has_transitive_vulnerabilities": False,
                     "visited": False}

    return new_component

def get_severity_by_score(score):
    score = float(score)
    if score >= 9:
        return "critical"
    elif score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    elif score > 0:
        return "low"
    else:
        return "information"


def parse_vulnerability_data(vulnerability):
    vuln_id = vulnerability["id"]

    vuln_severity = None
    vuln_score = 0.0
    vuln_vector = "-"
    if "ratings" in vulnerability:
        for rating in vulnerability["ratings"]:
            if "method" not in rating:
                continue
            for preferred_rating_method in PREFERRED_VULNERABILITY_RATING_METHODS_ORDER:
                if rating["method"] == preferred_rating_method:
                    if "severity" in rating:
                        rating_vuln_severity = rating["severity"]
                        if rating_vuln_severity.lower() in VALID_SEVERITIES:
                            if rating_vuln_severity.lower() == "info":
                                rating_vuln_severity = "information"
                            vuln_severity = rating_vuln_severity.lower()
                            if "score" in rating:
                                vuln_score = float(rating["score"])
                            if "vector" in rating:
                                vuln_vector = rating["vector"]
                            break
                    if "score" in rating:
                        vuln_severity = get_severity_by_score(rating["score"])
                        vuln_score = float(rating["score"])
                        if "vector" in rating:
                            vuln_vector = rating["vector"]
                        break


    if vuln_severity is None:
        if "ratings" not in vulnerability:
            custom_print(f"WARNING: vulnerability with id '{vulnerability['id']}' does not have a 'ratings' field. I'll set a default 'INFORMATION' severity...")
            vuln_severity = get_severity_by_score(0)
        elif len(vulnerability["ratings"]) == 0:
            custom_print(f"WARNING: vulnerability with id '{vulnerability['id']}' does have an empty 'ratings' field. I'll set a default 'INFORMATION' severity...")
            vuln_severity = get_severity_by_score(0)
        else:
            for rating in vulnerability["ratings"]:
                if "severity" in rating:
                    rating_vuln_severity = rating["severity"]
                    if rating_vuln_severity.lower() in VALID_SEVERITIES:
                        vuln_severity = rating_vuln_severity.lower()
                        if "score" in rating:
                            vuln_score = float(rating["score"])
                        if "vector" in rating:
                            vuln_vector = rating["vector"]
                        break
                if "score" in rating:
                    vuln_severity = get_severity_by_score(rating["score"])
                    vuln_score = float(rating["score"])
                    if "vector" in rating:
                        vuln_vector = rating["vector"]
                    break

    if vuln_severity is None:
        custom_print(f"WARNING: could not detect severity of vulnerability with id '{vulnerability['id']}'. I'll set a default 'INFORMATION' severity...")
        vuln_severity = get_severity_by_score(0)

    return vuln_id, vuln_severity, vuln_score, vuln_vector


bom_ref_cache = {}
def get_bom_ref(component_json, all_bom_refs):
    global bom_ref_cache
    if "bom-ref" in component_json:
        bom_ref = component_json["bom-ref"]
        return bom_ref
    else:
        bom_ref_cache_key = f"{component_json['name']} - {component_json['version']}"
        if bom_ref_cache_key in bom_ref_cache:
            return bom_ref_cache[f"{component_json['name']} - {component_json['version']}"]

        custom_print(f"WARNING: component with name '{component_json['name']}' and version '{component_json['version']}' does not have a 'bom-ref'. I'll search for a match...")
        for potential_bom_ref in all_bom_refs:
            guessed_name_01 = f'{component_json["name"]}@{component_json["version"]}'
            guessed_name_02 = f'{component_json["name"]}::{component_json["version"]}'
            guessed_name_03 = f'{component_json["name"]}:{component_json["version"]}'

            for test in [guessed_name_01, guessed_name_02, guessed_name_03]:
                if potential_bom_ref.endswith(f"/{test}"):
                    custom_print(f"Match found: {potential_bom_ref}")
                    bom_ref_cache[bom_ref_cache_key] = potential_bom_ref
                    return potential_bom_ref
                if potential_bom_ref.endswith(f"/{test}:"):
                    custom_print(f"Match found: {potential_bom_ref}")
                    bom_ref_cache[bom_ref_cache_key] = potential_bom_ref
                    return potential_bom_ref
                if potential_bom_ref.endswith(f":{test}"):
                    bom_ref_cache[bom_ref_cache_key] = potential_bom_ref
                    custom_print(f"Match found: {potential_bom_ref}")
                    return potential_bom_ref
                if potential_bom_ref.endswith(f":{test}:"):
                    bom_ref_cache[bom_ref_cache_key] = potential_bom_ref
                    custom_print(f"Match found: {potential_bom_ref}")
                    return potential_bom_ref

        # another try with version not in the end of the string
        number_of_results = 0
        result = None
        for potential_bom_ref in all_bom_refs:
            guessed_name_01 = f'{component_json["name"]}@{component_json["version"]}'
            guessed_name_02 = f'{component_json["name"]}::{component_json["version"]}'
            guessed_name_03 = f'{component_json["name"]}:{component_json["version"]}'

            for test in [guessed_name_01, guessed_name_02, guessed_name_03]:
                if f"/{test}:" in bom_ref:
                    number_of_results += 1
                    result = potential_bom_ref
                elif f":{test}:" in bom_ref:
                    number_of_results += 1
                    result = potential_bom_ref
        if number_of_results == 1:  # I want just one result, otherwise it means the sbom is ambiguous and I can't make any educated guess
            bom_ref_cache[bom_ref_cache_key] = result
            return result

        custom_print(f"Match not found. I'll create a fake one.")
        bom_ref = f"{hash(json.dumps(component_json, sort_keys=True, cls=SetEncoder))}"
        bom_ref_cache[bom_ref_cache_key] = bom_ref
        return bom_ref


def create_or_update_bom_ref_entry(bom_refs, component):
    if component["bom-ref"] not in bom_refs:
        bom_refs[component["bom-ref"]] = {"name": component["name"] if "name" in component else "-", 
                                          "version": component["version"] if "version" in component else "-"}
    else:
        if bom_refs[component["bom-ref"]]["name"] == "-" and "name" in component:
            bom_refs[component["bom-ref"]]["name"] = component["name"]
        if bom_refs[component["bom-ref"]]["version"] == "-" and "version" in component:
            bom_refs[component["bom-ref"]]["version"] = component["version"]


def normalize_bom_ref(bom_refs, bom_ref, only_valid_components=True):
    for component_bom_ref, component_data in bom_refs.items():
        if only_valid_components is False:
            if bom_ref == component_bom_ref:
                return bom_ref
        else:
            if bom_ref == component_bom_ref and component_data["name"] != "-" and component_data["version"] != "-":
                return bom_ref

    for component_bom_ref, component_data in bom_refs.items():
        # look with version
        guessed_name_01 = f'{component_data["name"]}@{component_data["version"]}'
        guessed_name_02 = f'{component_data["name"]}::{component_data["version"]}'
        guessed_name_03 = f'{component_data["name"]}:{component_data["version"]}'

        for test in [guessed_name_01, guessed_name_02, guessed_name_03]:
            if bom_ref.endswith(f"/{test}"):
                return bom_ref
            if bom_ref.endswith(f"/{test}:"):
               return bom_ref
            if bom_ref.endswith(f":{test}"):
                return bom_ref
            if bom_ref.endswith(f":{test}:"):
                return bom_ref

    # another try with version not in the end of the string
    number_of_results = 0
    result = None
    for component_bom_ref, component_data in bom_refs.items():
        guessed_name_01 = f'{component_data["name"]}@{component_data["version"]}'
        guessed_name_02 = f'{component_data["name"]}::{component_data["version"]}'
        guessed_name_03 = f'{component_data["name"]}:{component_data["version"]}'

        for test in [guessed_name_01, guessed_name_02, guessed_name_03]:
            if f"/{test}:" in bom_ref:
                number_of_results += 1
                result = component_bom_ref
            elif f":{test}:" in bom_ref:
                number_of_results += 1
                result = component_bom_ref
    if number_of_results == 1:  # I want just one result, otherwise it means the sbom is ambiguous and I can't make any educated guess
        return result

    # final try: without version
    number_of_results = 0
    result = None
    for component_bom_ref, component_data in bom_refs.items():
        # look without version        
        if f'/{component_data["name"]}@' in bom_ref:
            number_of_results += 1
            result = component_bom_ref
        elif f'/{component_data["name"]}:' in bom_ref:
            number_of_results += 1
            result = component_bom_ref
        elif f':{component_data["name"]}:' in bom_ref:
            number_of_results += 1
            result = component_bom_ref
        elif f':{component_data["name"]}@' in bom_ref:
            number_of_results += 1
            result = component_bom_ref
    if number_of_results == 1:  # I want just one result, otherwise it means the sbom is ambiguous and I can't make any educated guess
        return result

    return None


def has_bom_ref_components(bom_refs, bom_ref):
    return normalize_bom_ref(bom_refs, bom_ref, only_valid_components=False) is not None


def add_nested_components(component, components, all_bom_refs):
    for child_key in ["services", "components"]:
        if child_key in component:
            for sub_component in component[child_key]:
                new_component = create_base_component(sub_component)
                bom_ref = get_bom_ref(sub_component, all_bom_refs)
                components[bom_ref] = new_component
                add_nested_components(sub_component, components, all_bom_refs)


def detect_nested_bom_refs(component, bom_refs):
    for child_key in ["services", "components"]:
        if child_key in component:
            for sub_component in component[child_key]:
                if "bom-ref" in sub_component:
                    create_or_update_bom_ref_entry(bom_refs, sub_component)


def get_all_bom_refs(data):
    bom_refs = {}
    meta_bom_ref_is_used = False

    root_keywords = []
    if "components" in data:
        root_keywords.append("components")
    if "services" in data:
        root_keywords.append("services")

    for root_keyword in root_keywords:
        for component in data[root_keyword]:
            if "bom-ref" in component:
                create_or_update_bom_ref_entry(bom_refs, component)

            detect_nested_bom_refs(component, bom_refs)

    for root_keyword in root_keywords:
        for component in data[root_keyword]:
            if "dependencies" in component:
                for dependency in component["dependencies"]:
                    if "ref" in dependency:
                        create_or_update_bom_ref_entry(bom_refs, {"bom-ref":  dependency["ref"]})

    if "dependencies" in data:
        for dependency in data["dependencies"]:
            if "ref" in dependency:
                create_or_update_bom_ref_entry(bom_refs, {"bom-ref":  dependency["ref"]})

            if "dependsOn" in dependency:
                for depends_on in dependency["dependsOn"]:
                    create_or_update_bom_ref_entry(bom_refs, {"bom-ref":  depends_on})

    if "metadata" in data:
        if "component" in data["metadata"]:
            if "bom-ref" in data["metadata"]["component"]:
                if has_bom_ref_components(bom_refs, data["metadata"]["component"]["bom-ref"]):
                    meta_bom_ref_is_used = True
                    create_or_update_bom_ref_entry(bom_refs, data["metadata"]["component"])

    return bom_refs, meta_bom_ref_is_used


def parse_licenses(component):
    licenses = set()
    if "licenses" in component:
        for license in component["licenses"]:
            if "license" in license:
                if "id" in license["license"]:
                    licenses.add(license["license"]["id"])
                elif "name" in license["license"]:
                    licenses.add(license["license"]["name"])
    return sorted(list(licenses))


def parse_metadata(data):
    metadata_info = {}

    metadata_field = None

    if "metadata" in data:
        metadata_field = data["metadata"]

    if metadata_field is not None:
        if "component" in metadata_field:
            metadata_info["Main Component"] = {}
            if "type" in metadata_field["component"]:
                metadata_info["Main Component"]["Type"] = metadata_field["component"]["type"]
            if "group" in metadata_field["component"]:
                metadata_info["Main Component"]["Group"] = metadata_field["component"]["group"]
            if "name" in metadata_field["component"]:
                metadata_info["Main Component"]["Name"] = metadata_field["component"]["name"]
            if "version" in metadata_field["component"]:
                metadata_info["Main Component"]["Version"] = metadata_field["component"]["version"]
            if "description" in metadata_field["component"]:
                metadata_info["Main Component"]["Description"] = metadata_field["component"]["description"]
            if "purl" in metadata_field["component"]:
                metadata_info["Main Component"]["PURL"] = metadata_field["component"]["purl"]

            if "properties" in metadata_field["component"]:
                for property_element in metadata_field["component"]["properties"]:
                    metadata_info["Main Component"][f'{property_element["name"][0].capitalize()}{property_element["name"][1:]}'] = property_element["value"]

    if "specVersion" in data:
        metadata_info["Spec Version"] = data["specVersion"]

    if "serialNumber" in data:
        metadata_info["Serial Number"] = data["serialNumber"]

    if "version" in data:
        metadata_info["Version"] = str(data["version"])

    if metadata_field is not None:
        if "tools" in metadata_field:
            counter = 0
            for tool in metadata_field["tools"]:
                counter += 1
                info_id = "Tool"
                if len(metadata_field["tools"]) > 1:
                    info_id = f"{info_id} #{counter}"

                metadata_info[info_id] = {}
                if "vendor" in tool:
                    metadata_info[info_id]["Vendor"] = tool["vendor"]
                if "name" in tool:
                    metadata_info[info_id]["Name"] = tool["name"]
                if "version" in tool:
                    metadata_info[info_id]["Version"] = tool["version"]

    return metadata_info


def parse_json_data(data):
    all_bom_refs, meta_bom_ref_is_used = get_all_bom_refs(data)

    guessed_bom_refs_cache = {}

    components = {}

    root_keywords = []
    if "components" in data:
        root_keywords.append("components")
    if "services" in data:
        root_keywords.append("services")

    if "metadata" in data:
        if "component" in data["metadata"]:
            component = data["metadata"]["component"]
            if meta_bom_ref_is_used is True:
                new_component = create_base_component(component)
                bom_ref = get_bom_ref(component, all_bom_refs)
                components[bom_ref] = new_component

    metadata_info = parse_metadata(data)

    for root_keyword in root_keywords:
        for component in data[root_keyword]:
            new_component = create_base_component(component)
            bom_ref = get_bom_ref(component, all_bom_refs)
            components[bom_ref] = new_component
            add_nested_components(component, components, all_bom_refs)

        # sometimes dependencies are declared inside a component, I'll check that now
        for component in data[root_keyword]:
            bom_ref = get_bom_ref(component, all_bom_refs)

            if "dependencies" in component:
                for dependency in component["dependencies"]:
                    depends_on = dependency["ref"]
                    if depends_on not in components:
                        if depends_on in guessed_bom_refs_cache:
                            depends_on = guessed_bom_refs_cache[depends_on]
                        else:
                            custom_print(f"WARNING: 'ref' '{depends_on}' is used in 'dependencies' inside a component but it's not declared in 'components'. I'll search for a match...")
                            guessed_bom_ref = normalize_bom_ref(all_bom_refs, depends_on)
                            guessed_bom_refs_cache[depends_on] = guessed_bom_ref

                            if guessed_bom_ref is None:
                                custom_print(f"Match not found. I'll create a fake one.")
                                components[depends_on] = create_fake_component(depends_on)
                            else:
                                custom_print(f"Match found: {guessed_bom_ref}")
                                depends_on = guessed_bom_ref

                    components[bom_ref]["depends_on"].add(depends_on)
                    components[depends_on]["dependency_of"].add(bom_ref)

        # sometimes vulnerabilities are declared inside a component, I'll check that now
        for component in data[root_keyword]:
            bom_ref = get_bom_ref(component, all_bom_refs)

            if "vulnerabilities" in component:
                for vulnerability in component["vulnerabilities"]:
                    vuln_id, vuln_severity, vuln_score, vuln_vector = parse_vulnerability_data(vulnerability)

                    vulnerability_data = {"id": vuln_id, "severity": vuln_severity, "score": vuln_score, "vector": vuln_vector}
                    if vulnerability_data not in components[bom_ref]["vulnerabilities"]:
                        components[bom_ref]["vulnerabilities"].append(vulnerability_data)
                    if VALID_SEVERITIES[vuln_severity] > VALID_SEVERITIES[components[bom_ref]["max_vulnerability_severity"]]:
                        components[bom_ref]["max_vulnerability_severity"] = vuln_severity

    if "dependencies" in data:
        for dependency in data["dependencies"]:
            bom_ref = dependency["ref"]
            if bom_ref not in components:
                if bom_ref in guessed_bom_refs_cache:
                    bom_ref = guessed_bom_refs_cache[bom_ref]
                else:
                    custom_print(f"WARNING: 'ref' '{bom_ref}' is used in 'dependencies' in a 'ref' field but it's not declared in 'components'. I'll search for a match...")
                    guessed_bom_ref = normalize_bom_ref(all_bom_refs, bom_ref)
                    guessed_bom_refs_cache[bom_ref] = guessed_bom_ref
                    if guessed_bom_ref is None:
                        custom_print(f"Match not found. I'll create a fake one.")
                        components[bom_ref] = create_fake_component(bom_ref)
                    else:
                        custom_print(f"Match found: {guessed_bom_ref}")
                        bom_ref = guessed_bom_ref

            if "dependsOn" in dependency:
                for depends_on in dependency["dependsOn"]:
                    if depends_on not in components:
                        if depends_on in guessed_bom_refs_cache:
                            depends_on = guessed_bom_refs_cache[depends_on]
                        else:
                            custom_print(f"WARNING: 'dependsOn' '{depends_on}' is used in 'dependencies' in a 'dependsOn' field but it's not declared in 'components'. I'll search for a match...")
                            guessed_bom_ref = normalize_bom_ref(all_bom_refs, depends_on)
                            guessed_bom_refs_cache[depends_on] = guessed_bom_ref
                            if guessed_bom_ref is None:
                                custom_print(f"Match not found. I'll create a fake one.")
                                components[depends_on] = create_fake_component(depends_on)
                            else:
                                custom_print(f"Match found: {guessed_bom_ref}")
                                depends_on = guessed_bom_ref

                    components[bom_ref]["depends_on"].add(depends_on)
                    components[depends_on]["dependency_of"].add(bom_ref)

    if "vulnerabilities" in data:
        for vulnerability in data["vulnerabilities"]:
            vuln_id, vuln_severity, vuln_score, vuln_vector = parse_vulnerability_data(vulnerability)

            for affects in vulnerability["affects"]:
                bom_ref = affects["ref"]
                if bom_ref not in components:
                    custom_print(f"WARNING: 'ref' '{bom_ref}' is used in 'vulnerabilities' but it's not declared in 'components'. I'll create a fake one.")
                    components[bom_ref] = create_fake_component(bom_ref)

                vulnerability_data = {"id": vuln_id, "severity": vuln_severity, "score": vuln_score, "vector": vuln_vector}
                if vulnerability_data not in components[bom_ref]["vulnerabilities"]:
                    components[bom_ref]["vulnerabilities"].append(vulnerability_data)
                if VALID_SEVERITIES[vuln_severity] > VALID_SEVERITIES[components[bom_ref]["max_vulnerability_severity"]]:
                    components[bom_ref]["max_vulnerability_severity"] = vuln_severity

    return components, metadata_info


def parse_string(input_string):
    custom_print("Parsing input string...")
    data = json.loads(input_string)
    return parse_json_data(data)


def parse_file(input_file_path):
    custom_print("Parsing input file...")
    with open(input_file_path, 'r') as file:
        data = json.load(file)
    return parse_json_data(data)


def prepare_chart_element_name(component):
    if component["version"] != "-":
        name = f'{html.escape(component["name"])} <b>{html.escape(component["version"])}</b>'
    else:
        name = f'{html.escape(component["name"])}'

    if len(component["vulnerabilities"]) > 0:
        name += "<br><br>Vulnerabilities:<br>"

        vulns = {}
        for vulnerability in component["vulnerabilities"]:
            vulns[f'<li>{html.escape(vulnerability["id"])} ({html.escape(vulnerability["severity"].title())})</li>'] = VALID_SEVERITIES[vulnerability["severity"]]

        vulns = dict(sorted(vulns.items(), key=lambda item: (-item[1], item[0])))

        vulns_to_be_shown = list(vulns.keys())
        if len(vulns_to_be_shown) > 10:
            vulns_to_be_shown = vulns_to_be_shown[:10]
            vulns_to_be_shown.append("<li>...</li>")


        name += "".join(vulns_to_be_shown)

    if len(component["license"]) > 0:
        if len(component["vulnerabilities"]) == 0:
            name += "<br>"
        name += "<br>License:<br>"

        licenses = []
        for license in component["license"]:
            licenses.append(f'<li>{html.escape(license)}</li>')

        if len(licenses) > 10:
            licenses = licenses[:10]
            licenses.append("<li>...</li>")

        name += "".join(licenses)

    return name


def determine_style(component):
    if component["max_vulnerability_severity"] != "clean":
        return STYLES[component["max_vulnerability_severity"]]
    if component["has_transitive_vulnerabilities"] is True:
        return TRANSITIVE_VULN_STYLE
    else:
        return STYLES[component["max_vulnerability_severity"]]


def add_transitive_vulnerabilities_to_component(component, vulnerabilities):
    for vulnerability in vulnerabilities:
        if vulnerability not in component["transitive_vulnerabilities"]:
            component["transitive_vulnerabilities"].append(vulnerability)


def format_dependency_chain(parents_branch, depends_on):
    parents_branch.append(depends_on)
    return " --> ".join(parents_branch)


def get_children(components, component, parents):
    children = []
    value = 0
    has_vulnerable_children_or_is_vulnerable = False
    if len(component["vulnerabilities"]) > 0:
        has_vulnerable_children_or_is_vulnerable = True
    for depends_on in component["depends_on"]:
        parents_branch = copy.deepcopy(parents)
        child_name = prepare_chart_element_name(components[depends_on])
        child_component = components[depends_on]
        child_component["visited"] = True
        if depends_on not in parents_branch:  # this is done to avoid infinite recursion in case of circular dependencies
            parents_branch.append(depends_on)
            child_children, children_value, has_vulnerable_children_or_is_vulnerable = get_children(components, child_component, parents_branch)
            if len(child_component["vulnerabilities"]) > 0 or child_component["has_transitive_vulnerabilities"] is True or has_vulnerable_children_or_is_vulnerable is True:
                component["has_transitive_vulnerabilities"] = True
                add_transitive_vulnerabilities_to_component(component, child_component["vulnerabilities"])
                add_transitive_vulnerabilities_to_component(component, child_component["transitive_vulnerabilities"])
                has_vulnerable_children_or_is_vulnerable = True

            value += children_value
            
            children.append({"name": child_name,
                             "children": child_children,
                             "value": children_value,
                             "itemStyle": determine_style(child_component)
                             })
        else:
            custom_print(f"WARNING: component with bom-ref '{depends_on}' may be a circular dependency. Dependency chain: {format_dependency_chain(parents_branch, depends_on)}")
            value += 1
            for child_depends_on in child_component["depends_on"]:
                child_depends_on = components[child_depends_on]
                if len(child_depends_on["vulnerabilities"]) > 0 or child_depends_on["has_transitive_vulnerabilities"] is True:
                    child_component["has_transitive_vulnerabilities"] = True
                    add_transitive_vulnerabilities_to_component(child_component, child_depends_on["vulnerabilities"])
                    add_transitive_vulnerabilities_to_component(child_component, child_depends_on["transitive_vulnerabilities"])
                

            children.append({"name": child_name,
                             "children": [],
                             "value": 1,
                             "itemStyle": determine_style(child_component)
                             })

    if value == 0:
        value = 1

    return children, value, has_vulnerable_children_or_is_vulnerable


def add_root_component(components, component, data, bom_ref):
    component["visited"] = True
    parents = [bom_ref]
    root_name = prepare_chart_element_name(component)
    root_children, root_value, has_vulnerable_children_or_is_vulnerable = get_children(components, component, parents)

    if has_vulnerable_children_or_is_vulnerable is True:
        component["has_transitive_vulnerabilities"] = True
        for depends_on in component["depends_on"]:
            child = components[depends_on]
            add_transitive_vulnerabilities_to_component(component, child["vulnerabilities"])
            add_transitive_vulnerabilities_to_component(component, child["transitive_vulnerabilities"])

    new_element = {"name": root_name,
                   "children": root_children,
                   "value": root_value,
                   "itemStyle": determine_style(component)
                   }
    data.append(new_element)


def build_echarts_data(components):
    data = []

    for bom_ref, component in components.items():
        if len(component["dependency_of"]) != 0:
            continue

        add_root_component(components, component, data, bom_ref)

    return data


def double_check_if_all_components_were_taken_into_account(components, echart_data):
    # this should happen only for circular dependencies
    for bom_ref, component in components.items():
        if component["visited"] is False:
            add_root_component(components, component, echart_data, bom_ref)


def component_badge_for_table(component):
    component_on_display = ""

    if component["max_vulnerability_severity"] == "critical":
        badge_class = 'bg-dark-red'
    elif component["max_vulnerability_severity"] == "high":
        badge_class = 'bg-danger'
    elif component["max_vulnerability_severity"] == "medium":
        badge_class = 'bg-orange'
    elif component["max_vulnerability_severity"] == "low":
        badge_class = 'bg-yellow'
    elif component["max_vulnerability_severity"] in ["information", "info"]:
        badge_class = 'bg-success'
    elif component["max_vulnerability_severity"] == "clean":
        if component["has_transitive_vulnerabilities"]:
            badge_class = 'bg-light-blue'
        else:
            badge_class = 'bg-secondary'

    component_on_display += f'<span class="badge {badge_class}">' + html.escape(component["name"])
    if component["version"] != "-":
        component_on_display += " " + html.escape(component["version"])
    return component_on_display + "</span>"


def get_vulnerability_badge_by_severity(severity):
    if severity == "critical":
        return 'bg-dark-red'
    elif severity == "high":
        return 'bg-danger'
    elif severity == "medium":
        return 'bg-orange'
    elif severity == "low":
        return 'bg-yellow'
    elif severity in ["information", "info"]:
        return 'bg-success'
    return ''

def vulnerability_badge_for_table(component, key="vulnerabilities"):
    vulns = {}
    for vulnerability in component[key]:
        badge_class = get_vulnerability_badge_by_severity(vulnerability["severity"])

        vulns[f'<span class="badge {badge_class}">{html.escape(vulnerability["severity"].title())} &#x2192; {html.escape(vulnerability["id"])}</span>'] = VALID_SEVERITIES[vulnerability["severity"]]
    vulns = vulns = dict(sorted(vulns.items(), key=lambda item: (-item[1], item[0])))
    vulns_to_be_shown = list(vulns.keys())
    return vulns_to_be_shown


def license_badge_for_table(component):
    licenses = []
    for license in component["license"]:
        licenses.append(f'<span class="badge border border-dark text-dark">{html.escape(license)}</span>')
    return licenses


def build_components_table_content(components):
    rows = ["""<thead>
        <tr>
            <th>Component</th>
            <th>Depends on</th>
            <th>Dependency of</th>
            <th>Direct <br>vulnerabilities</th>
            <th>Transitive <br>vulnerabilities</th>
            <th>License</th>
        </tr>
        <tr>
            <th><input type="text" placeholder="Search Component" class="form-control search-in-table-comp"></th>
            <th><input type="text" placeholder="Search Depends on" class="form-control search-in-table-comp"></th>
            <th><input type="text" placeholder="Search Dependency of" class="form-control search-in-table-comp"></th>
            <th><input type="text" placeholder="Search Direct vulnerabilities" class="form-control search-in-table-comp"></th>
            <th><input type="text" placeholder="Search Transitive vulnerabilities" class="form-control search-in-table-comp"></th>
            <th><input type="text" placeholder="Search License" class="form-control search-in-table-comp"></th>
        </tr>
    </thead>"""]
    rows.append("<tbody>")
    for bom_ref, component in components.items():
        new_row = "<tr>"

        new_row += "<td>" + component_badge_for_table(component) + "</td>"


        if len(component["depends_on"]) == 0:
            new_row += "<td>-</td>"
        else:
            new_row += "<td>"
            depends_on_components_list = []
            for depends_on in component["depends_on"]:
                component_depends_on = components[depends_on]
                component_depends_on_display = component_badge_for_table(component_depends_on)
                depends_on_components_list.append(component_depends_on_display)

            new_row += '<span style="display: none;">, </span><br>'.join(depends_on_components_list)
            new_row += "</td>"

        if len(component["dependency_of"]) == 0:
            new_row += "<td>-</td>"
        else:
            new_row += "<td>"
            dependency_of_components_list = []
            for dependency_of in component["dependency_of"]:
                component_dependency_of = components[dependency_of]
                component_dependency_of_display = component_badge_for_table(component_dependency_of)
                dependency_of_components_list.append(component_dependency_of_display)
            new_row += '<span style="display: none;">, </span><br>'.join(dependency_of_components_list)
            new_row += "</td>"

        if len(component["vulnerabilities"]) == 0:
            new_row += "<td>-</td>"
        else:
            vulns_to_be_shown = vulnerability_badge_for_table(component)
            new_row += "<td>" + '<span style="display: none;">, </span><br>'.join(vulns_to_be_shown) + "</td>"

        if len(component["transitive_vulnerabilities"]) == 0:
            new_row += "<td>-</td>"
        else:
            vulns_to_be_shown = vulnerability_badge_for_table(component, key="transitive_vulnerabilities")
            new_row += "<td>" + '<span style="display: none;">, </span><br>'.join(vulns_to_be_shown) + "</td>"

        if len(component["license"]) == 0:
            new_row += "<td>-</td>"
        else:
            licenses_to_be_shown = license_badge_for_table(component)
            new_row += "<td>" + '<span style="display: none;">, </span><br>'.join(licenses_to_be_shown) + "</td>"

        new_row += "</tr>\n"

        rows.append(new_row)

    rows.append("</tbody>")

    return "".join(rows)


def build_vulnerabilities_table_content(vulnerabilities, components):
    rows = ["""<thead>
        <tr>
            <th>Vulnerability</th>
            <th>Severity</th>
            <th>Score</th>
            <th>Vector</th>
            <th>Directly vulnerable <br>components</th>
            <th>Transitively vulnerable <br>components</th>
        </tr>
        <tr>
            <th><input type="text" placeholder="Search Vulnerability" class="form-control search-in-table-vuln"></th>
            <th><input type="text" placeholder="Search Severity" class="form-control search-in-table-vuln"></th>
            <th><input type="text" placeholder="Search Score" class="form-control search-in-table-vuln"></th>
            <th><input type="text" placeholder="Search Vector" class="form-control search-in-table-vuln"></th>
            <th><input type="text" placeholder="Search Directly vulnerable components" class="form-control search-in-table-vuln"></th>
            <th><input type="text" placeholder="Search Transitively vulnerable components" class="form-control search-in-table-vuln"></th>
        </tr>
    </thead>"""]
    rows.append("<tbody>")

    for _, vulnerability in vulnerabilities.items():
        rows.append("<tr>")
        badge_class = get_vulnerability_badge_by_severity(vulnerability["severity"])
        rows.append("<td>" + f'<span class="badge {badge_class}">{html.escape(vulnerability["id"])}</span>' + "</td>")
        
        rows.append("<td>" + f'{html.escape(vulnerability["severity"].title())}' + "</td>")
        rows.append("<td>" + f'{vulnerability["score"]}' + "</td>")
        rows.append("<td>" + f'{html.escape(vulnerability["vector"])}' + "</td>")

        if len(vulnerability["directly_vulnerable_components"]) == 0:
            rows.append("<td>-</td>")
        else:
            vulnerable_components_td = "<td>"
            content_values = []
            for component in vulnerability["directly_vulnerable_components"]:
                content_values.append(component_badge_for_table(components[component]))
            vulnerable_components_td += '<span style="display: none;">, </span><br>'.join(content_values) + "</td>"
            rows.append(vulnerable_components_td)

        if len(vulnerability["transitively_vulnerable_components"]) == 0:
            rows.append("<td>-</td>")
        else:
            vulnerable_components_td = "<td>"
            content_values = []
            for component in vulnerability["transitively_vulnerable_components"]:
                content_values.append(component_badge_for_table(components[component]))
            vulnerable_components_td += '<span style="display: none;">, </span><br>'.join(content_values) + "</td>"
            rows.append(vulnerable_components_td)

        rows.append("</tr>")

    rows.append("</tbody>")

    return "".join(rows)


def build_metadata_table_content(metadata_info, counter_critical, counter_high, counter_medium, counter_low, counter_info, components):
    rows = []

    # headers
    rows.append("<thead>")
    rows.append("<tr>")
    rows.append(f"<th>No. of Components</th>")
    rows.append(f"<th>Vulnerabilities</th>")
    for header, _ in metadata_info.items():
        rows.append(f"<th>{html.escape(header)}</th>")
    rows.append("</tr>")
    rows.append("</thead>")

    # body
    rows.append("<tbody>")
    rows.append("<tr>")

    rows.append(f"<td>{len(components)}</td>")

    vulnerabilities_td = ""
    if counter_critical > 0:
        vulnerabilities_td += f'<span class="badge bg-dark-red">{counter_critical}</span>&nbsp;'
    else:
        vulnerabilities_td += f'<span class="badge bg-dark-red opaque">{counter_critical}</span>&nbsp;'
    if counter_high > 0:
        vulnerabilities_td += f'<span class="badge bg-danger">{counter_high}</span>&nbsp;'
    else:
        vulnerabilities_td += f'<span class="badge bg-danger opaque">{counter_high}</span>&nbsp;'
    if counter_medium > 0:
        vulnerabilities_td += f'<span class="badge bg-orange">{counter_medium}</span>&nbsp;'
    else:
        vulnerabilities_td += f'<span class="badge bg-orange opaque">{counter_medium}</span>&nbsp;'
    if counter_low > 0:
        vulnerabilities_td += f'<span class="badge bg-yellow">{counter_low}</span>&nbsp;'
    else:
        vulnerabilities_td += f'<span class="badge bg-yellow opaque">{counter_low}</span>&nbsp;'
    if counter_info > 0:
        vulnerabilities_td += f'<span class="badge bg-success">{counter_info}</span>&nbsp;'
    else:
        vulnerabilities_td += f'<span class="badge bg-success opaque">{counter_info}</span>&nbsp;'

    rows.append(f"<td>{vulnerabilities_td}</td>")

    for _, metadata_content in metadata_info.items():
        if isinstance(metadata_content, dict):
            rows.append("<td>")
            content_values = []
            for content_key, content_value in metadata_content.items():
                content_values.append(f'<i>{html.escape(content_key)}</i>&nbsp;&#x2192;&nbsp;{html.escape(content_value)}')
            rows.append('<span style="display: none;">, </span><br>'.join(content_values) + "</td>"
                    )
            rows.append("</td>")
        else:
            rows.append("<td>" + html.escape(f"{metadata_content}") + "</td>")

    rows.append("</tr>")
    rows.append("</tbody>")

    return "".join(rows)


def write_output_file(html_content, output_file_path):
    with open(output_file_path, "w") as text_file:
        text_file.write(html_content)


def get_only_vulnerable_components(components):
    vulnerable_components = {}

    # populate vulnerable components
    for component_bom_ref, component in components.items():
        if len(component["vulnerabilities"]) == 0 and len(component["transitive_vulnerabilities"]) == 0:
            continue  # component is not vulnerable in any way
        
        vulnerable_component = {"name": component["name"],
                                "version": component["version"],
                                "type": component["type"],
                                "license": copy.deepcopy(component["license"]),
                                "depends_on": copy.deepcopy(component["depends_on"]),
                                "dependency_of": copy.deepcopy(component["dependency_of"]),
                                "vulnerabilities": copy.deepcopy(component["vulnerabilities"]),
                                "transitive_vulnerabilities": copy.deepcopy(component["transitive_vulnerabilities"]),
                                "max_vulnerability_severity": component["max_vulnerability_severity"],
                                "has_transitive_vulnerabilities": component["has_transitive_vulnerabilities"],
                                "visited": False}
        vulnerable_components[component_bom_ref] = vulnerable_component

    # clean not vulnerable dependency relationships
    vulnerable_components_bom_refs = set(vulnerable_components.keys())
    for component_bom_ref, component in vulnerable_components.items():
        vulnerable_depends_on = set(component["depends_on"]) & vulnerable_components_bom_refs
        component["depends_on"] = vulnerable_depends_on
        vulnerable_dependency_of = set(component["dependency_of"]) & vulnerable_components_bom_refs
        component["dependency_of"] = vulnerable_dependency_of

    return vulnerable_components


def parse_vulnerabilities(components):
    vulnerabilities = {}

    counter_critical = 0
    counter_high = 0
    counter_medium = 0
    counter_low = 0
    counter_info = 0

    # populate vulnerable components
    for component_bom_ref, component in components.items():
        if len(component["vulnerabilities"]) == 0 and len(component["transitive_vulnerabilities"]) == 0:
            continue  # component is not vulnerable in any way

        for vulnerability in component["vulnerabilities"]:
            vuln_key = f"{vulnerability['id']}-{vulnerability['severity']}-{vulnerability['score']}"

            if vuln_key not in vulnerabilities:
                vulnerabilities[vuln_key] = {"id": vulnerability['id'],
                                             "severity": vulnerability['severity'],
                                             "score": vulnerability['score'],
                                             "vector": vulnerability['vector'],
                                             "directly_vulnerable_components": set(),
                                             "transitively_vulnerable_components": set()}

                if vulnerability['severity'] == "critical":
                    counter_critical += 1
                elif vulnerability['severity'] == "high":
                    counter_high += 1
                elif vulnerability['severity'] == "medium":
                    counter_medium += 1
                elif vulnerability['severity'] == "low":
                    counter_low += 1
                else:
                    counter_info += 1

            vulnerabilities[vuln_key]["directly_vulnerable_components"].add(component_bom_ref)

        for vulnerability in component["transitive_vulnerabilities"]:
            vuln_key = f"{vulnerability['id']}-{vulnerability['severity']}-{vulnerability['score']}"

            if vuln_key not in vulnerabilities:
                vulnerabilities[vuln_key] = {"id": vulnerability['id'],
                                             "severity": vulnerability['severity'],
                                             "score": vulnerability['score'],
                                             "vector": vulnerability['vector'],
                                             "directly_vulnerable_components": set(),
                                             "transitively_vulnerable_components": set()}

                if vulnerability['severity'] == "critical":
                    counter_critical += 1
                elif vulnerability['severity'] == "high":
                    counter_high += 1
                elif vulnerability['severity'] == "medium":
                    counter_medium += 1
                elif vulnerability['severity'] == "low":
                    counter_low += 1
                else:
                    counter_info += 1

            vulnerabilities[vuln_key]["transitively_vulnerable_components"].add(component_bom_ref)


    return vulnerabilities, counter_critical, counter_high, counter_medium, counter_low, counter_info


def main_cli(input_file_path, output_file_path):
    if not os.path.exists(input_file_path):
        custom_print(f"File does not exist: '{input_file_path}'")
        exit()

    try:
        components, metadata_info = parse_file(input_file_path)
    except Exception as e:
        custom_print(f"Error parsing input file: {e}")
        exit()

    # chart with all components
    echart_data_all_components = build_echarts_data(components)
    double_check_if_all_components_were_taken_into_account(components, echart_data_all_components)

    vulnerabilities, counter_critical, counter_high, counter_medium, counter_low, counter_info = parse_vulnerabilities(components)

    # chart with only vulnerable components
    vulnerable_components = get_only_vulnerable_components(components)
    echart_data_vulnerable_components = build_echarts_data(vulnerable_components)
    double_check_if_all_components_were_taken_into_account(vulnerable_components, echart_data_vulnerable_components)

    components_table_content = build_components_table_content(components)
    metadata_table_content = build_metadata_table_content(metadata_info, counter_critical, counter_high, counter_medium, counter_low, counter_info, components)
    vulnerabilities_table_content = build_vulnerabilities_table_content(vulnerabilities, components)
    
    html_content = HTML_TEMPLATE.replace("<CHART_DATA_HERE>", json.dumps(echart_data_all_components, indent=2))
    html_content = html_content.replace("<CHART_DATA_VULN_HERE>", json.dumps(echart_data_vulnerable_components, indent=2))
    html_content = html_content.replace("<FILE_NAME_HERE>", html.escape(os.path.basename(input_file_path)))
    html_content = html_content.replace("<COMPONENTS_TABLE_HERE>", components_table_content)
    html_content = html_content.replace("<VULNERABILITIES_TABLE_HERE>", vulnerabilities_table_content)
    html_content = html_content.replace("<METADATA_TABLE_HERE>", metadata_table_content)
    
    write_output_file(html_content, output_file_path)
    custom_print("Done.")


def main_web(input_string):
    try:
        components, metadata_info = parse_string(input_string)
    except Exception as e:
        custom_print(f"Error parsing input string: {e}")
        exit()

    # chart with all components
    echart_data_all_components = build_echarts_data(components)
    double_check_if_all_components_were_taken_into_account(components, echart_data_all_components)
    echart_data_all_components = json.dumps(echart_data_all_components, indent=2)

    vulnerabilities, counter_critical, counter_high, counter_medium, counter_low, counter_info = parse_vulnerabilities(components)

    # chart with only vulnerable components
    vulnerable_components = get_only_vulnerable_components(components)
    echart_data_vulnerable_components = build_echarts_data(vulnerable_components)
    double_check_if_all_components_were_taken_into_account(vulnerable_components, echart_data_vulnerable_components)
    echart_data_vulnerable_components = json.dumps(echart_data_vulnerable_components, indent=2)

    components_table_content = build_components_table_content(components)
    metadata_table_content = build_metadata_table_content(metadata_info, counter_critical, counter_high, counter_medium, counter_low, counter_info, components)

    vulnerabilities_table_content = build_vulnerabilities_table_content(vulnerabilities, components)
    
    return echart_data_all_components, echart_data_vulnerable_components, components_table_content, metadata_table_content, vulnerabilities_table_content


if __name__ == "__main__":
    custom_print(f'''
 ▗▄▄▖▗▖ ▗▖▗▖  ▗▖ ▗▄▄▖▗▖ ▗▖▗▄▄▄▖▗▖  ▗▖▗▄▄▄▖
▐▌   ▐▌ ▐▌▐▛▚▖▐▌▐▌   ▐▌ ▐▌  █  ▐▛▚▖▐▌▐▌   
 ▝▀▚▖▐▌ ▐▌▐▌ ▝▜▌ ▝▀▚▖▐▛▀▜▌  █  ▐▌ ▝▜▌▐▛▀▀▘
▗▄▄▞▘▝▚▄▞▘▐▌  ▐▌▗▄▄▞▘▐▌ ▐▌▗▄█▄▖▐▌  ▐▌▐▙▄▄▖ v{VERSION}
    ''')

    parser = argparse.ArgumentParser(description=f"{NAME}: actionable CycloneDX visualization")
    parser.add_argument("-v", "--version", help="show program version", action="store_true")
    parser.add_argument("-i", "--input", help="path of input CycloneDX file")
    parser.add_argument("-o", "--output", help="path of output HTML file")
    args = parser.parse_args()

    if args.version:
        exit()

    if not args.input or not args.output:
        parser.print_help()
        exit()

    input_file_path = args.input
    output_file_path = args.output
    main_cli(input_file_path, output_file_path)


if __name__ == "__web__":
    echart_data_all_components, echart_data_vulnerable_components, components_table_content, metadata_table_content, vulnerabilities_table_content = main_web(INPUT_DATA)
    OUTPUT_CHART_DATA = echart_data_all_components
    OUTPUT_CHART_DATA_VULNERABLE_COMPONENTS = echart_data_vulnerable_components
    OUTPUT_COMPONENTS_TABLE_DATA = components_table_content
    OUTPUT_METADATA_TABLE_DATA = metadata_table_content
    OUTPUT_VULNERABILITIES_TABLE_DATA = vulnerabilities_table_content

