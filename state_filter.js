/*
 * Sunshine - analysis state filter (CycloneDX vulnerabilities[].analysis.state).
 *
 * Nothing is removed from the report: all vulnerabilities are shown by default and the user can
 * hide groups of states (resolved, not_affected, false_positive, ...) with the toggle bar.
 * Python annotates the generated HTML/chart data with state groups; this file applies the filter
 * client-side to tables, summary counters, sunburst charts and chart tooltips.
 *
 * Used both by index.html (loaded as an external script) and inlined into the CLI-generated HTML.
 */
(function () {
    var GROUPS = [
        { key: "exploitable", label: "Exploitable" },
        { key: "in_triage", label: "In triage" },
        { key: "unassigned", label: "Unassigned" },
        { key: "resolved", label: "Resolved" },
        { key: "not_affected", label: "Not affected" },
        { key: "false_positive", label: "False positive" },
        { key: "other", label: "Other" }
    ];

    var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, information: 0, unknown: -1 };
    var RANK_COLOR = { 4: "#a10a0a", 3: "#ff4633", 2: "#ff9335", 1: "#fccd58", 0: "#7dd491", "-1": "#7dd491" };
    var RANK_BADGE = { 4: "bg-dark-red", 3: "bg-danger", 2: "bg-orange", 1: "bg-yellow", 0: "bg-success", "-1": "bg-success" };
    var ALL_BADGES = ["bg-dark-red", "bg-danger", "bg-orange", "bg-yellow", "bg-success", "bg-light-blue", "bg-secondary"];
    var TRANSITIVE_COLOR = "#9fc5e8";
    var GREY = "#bcbcbc";
    var NONE = -99;
    var TABLE_IDS = ["components-table", "vulnerabilities-table"];
    var VULN_TABLE_ID = "vulnerabilities-table";

    var active = {};
    GROUPS.forEach(function (g) { active[g.key] = true; });

    function isActive(groupsString) {
        if (!groupsString) { return true; }
        return groupsString.split(" ").some(function (g) { return active[g] !== false; });
    }

    function getTable(id) {
        if (typeof $ === "undefined" || !$.fn || !$.fn.dataTable) { return null; }
        if (!$.fn.dataTable.isDataTable("#" + id)) { return null; }
        return $("#" + id).DataTable();
    }

    // "critical:resolved;high:unassigned" -> best visible severity rank (or NONE)
    function bestRankFromString(str) {
        var best = NONE;
        if (!str) { return best; }
        str.split(";").forEach(function (item) {
            var parts = item.split(":");
            if (active[parts[1]] === false) { return; }
            var rank = SEV_RANK[parts[0]];
            if (rank === undefined) { rank = 0; }
            if (rank > best) { best = rank; }
        });
        return best;
    }

    function bestRankFromPairs(pairs) {
        var best = NONE;
        (pairs || []).forEach(function (pair) {
            if (active[pair[1]] === false) { return; }
            var rank = SEV_RANK[pair[0]];
            if (rank === undefined) { rank = 0; }
            if (rank > best) { best = rank; }
        });
        return best;
    }

    // ---------- chart ----------

    function styleFor(node) {
        var direct = bestRankFromPairs(node.dv);
        if (direct !== NONE) { return { color: RANK_COLOR[direct], borderWidth: 2 }; }
        if (bestRankFromPairs(node.tv) !== NONE) { return { color: TRANSITIVE_COLOR, borderWidth: 2 }; }
        return { color: GREY, borderWidth: 2 };
    }

    function isVisiblyVulnerable(node) {
        return bestRankFromPairs(node.dv) !== NONE || bestRankFromPairs(node.tv) !== NONE;
    }

    function transformNodes(nodes, prune) {
        var result = [];
        nodes.forEach(function (node) {
            var kids = transformNodes(node.children || [], prune);
            if (prune && !isVisiblyVulnerable(node)) {
                // not vulnerable with the current toggles: promote its (vulnerable) descendants
                Array.prototype.push.apply(result, kids);
                return;
            }
            var copy = {};
            Object.keys(node).forEach(function (k) { copy[k] = node[k]; });
            copy.children = kids;
            if (prune) {
                var sum = 0;
                kids.forEach(function (k) { sum += k.value; });
                copy.value = sum > 0 ? sum : 1;
            }
            copy.itemStyle = styleFor(node);
            result.push(copy);
        });
        return result;
    }

    var chartSources = {};  // dom id -> { data, prune }

    window.sunshineRegisterChart = function (domId, data, prune) {
        chartSources[domId] = { data: data, prune: prune === true };
    };

    function refreshChart(domId) {
        var source = chartSources[domId];
        var dom = document.getElementById(domId);
        if (!source || !dom || typeof echarts === "undefined") { return; }
        var chart = echarts.getInstanceByDom(dom);
        if (!chart) { return; }
        var option = chart.getOption();
        if (!option || !option.series || !option.series[0]) { return; }
        var series = option.series[0];
        series.data = transformNodes(source.data, source.prune);
        chart.setOption({ series: [series] }, { replaceMerge: ["series"] });
    }

    window.sunshineFilterTooltip = function (name) {
        return String(name)
            .replace(/<li data-state="([^"]*)">[\s\S]*?<\/li>/g, function (match, groups) {
                return isActive(groups) ? match : "";
            })
            .replace(/<br><br>Vulnerabilities:<br><ul style='margin-bottom: 0'><\/ul>/, "");
    };

    // ---------- tables ----------

    function allNodes(api) {
        return $(api.rows().nodes());
    }

    function updateStateItems(api) {
        allNodes(api).find(".state-item").each(function () {
            this.style.display = isActive(this.getAttribute("data-state")) ? "" : "none";
        });
    }

    function updateComponentBadges(api) {
        allNodes(api).find(".comp-badge").each(function () {
            var best = bestRankFromString(this.getAttribute("data-dv"));
            var badge;
            if (best !== NONE) {
                badge = RANK_BADGE[best];
            } else if (bestRankFromString(this.getAttribute("data-tv")) !== NONE) {
                badge = "bg-light-blue";
            } else {
                badge = "bg-secondary";
            }
            var el = this;
            ALL_BADGES.forEach(function (c) { el.classList.remove(c); });
            el.classList.add(badge);
        });
    }

    function updateSummaryCounters(vulnApi) {
        var counters = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        allNodes(vulnApi).each(function () {
            if (isActive(this.getAttribute("data-states"))) {
                var sev = this.getAttribute("data-sev");
                if (counters[sev] !== undefined) { counters[sev] += 1; }
            }
        });
        document.querySelectorAll(".sev-count").forEach(function (el) {
            var count = counters[el.getAttribute("data-sev")] || 0;
            el.textContent = count;
            if (count > 0) { el.classList.remove("opaque"); } else { el.classList.add("opaque"); }
        });
    }

    function installRowFilter() {
        if (window.sunshineRowFilterInstalled || typeof $ === "undefined" || !$.fn || !$.fn.dataTable) { return; }
        window.sunshineRowFilterInstalled = true;
        $.fn.dataTable.ext.search.push(function (settings, data, dataIndex) {
            if (!settings.nTable || settings.nTable.id !== VULN_TABLE_ID) { return true; }
            var row = settings.aoData[dataIndex];
            if (!row || !row.nTr) { return true; }
            return isActive(row.nTr.getAttribute("data-states"));
        });
    }

    window.sunshineApplyStateFilter = function () {
        installRowFilter();
        TABLE_IDS.forEach(function (id) {
            var api = getTable(id);
            if (!api) { return; }
            updateStateItems(api);
            updateComponentBadges(api);
        });
        var vulnApi = getTable(VULN_TABLE_ID);
        if (vulnApi) {
            updateSummaryCounters(vulnApi);
            vulnApi.draw(false);
        }
        Object.keys(chartSources).forEach(refreshChart);
        updateFilterNote();
    };

    // ---------- toggle bar ----------

    function countVulnerabilities() {
        var counts = {};
        var total = 0;
        var hidden = 0;
        var vulnApi = getTable(VULN_TABLE_ID);
        if (!vulnApi) { return null; }
        allNodes(vulnApi).each(function () {
            var groups = (this.getAttribute("data-states") || "").split(" ").filter(Boolean);
            total += 1;
            if (!isActive(this.getAttribute("data-states"))) { hidden += 1; }
            groups.forEach(function (g) { counts[g] = (counts[g] || 0) + 1; });
        });
        return { counts: counts, total: total, hidden: hidden };
    }

    function updateFilterNote() {
        var note = document.getElementById("state-filter-note");
        if (!note) { return; }
        var info = countVulnerabilities();
        if (!info || info.hidden === 0) { note.textContent = ""; return; }
        note.textContent = info.hidden + " of " + info.total + " vulnerabilities hidden by state filter";
    }

    // ---------- column dropdowns (vulnerabilities table) ----------

    function escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }

    function cellValues(cell, filterType) {
        if (!cell) { return []; }
        if (filterType === "severity") {
            var text = cell.textContent.trim();
            return text ? [text] : [];
        }
        var values = [];
        $(cell).find(".state-item").each(function () {
            var text = this.textContent.replace(/,\s*$/, "").trim();
            if (text && text !== "-") { values.push(text); }
        });
        return values;
    }

    window.sunshineBuildColumnDropdowns = function () {
        var api = getTable(VULN_TABLE_ID);
        if (!api) { return; }
        var nodes = api.rows().nodes().toArray();
        $(api.table().container()).find("thead select.search-select").each(function () {
            var select = this;
            var filterType = select.getAttribute("data-filter");
            var columnIndex = $(select).parent().index();
            var counts = {};
            nodes.forEach(function (tr) {
                var seen = {};
                cellValues(tr.cells[columnIndex], filterType).forEach(function (v) {
                    if (!seen[v]) { seen[v] = true; counts[v] = (counts[v] || 0) + 1; }
                });
            });
            var values = Object.keys(counts);
            if (filterType === "severity") {
                values.sort(function (a, b) {
                    var ra = SEV_RANK[a.toLowerCase()]; var rb = SEV_RANK[b.toLowerCase()];
                    return (rb === undefined ? -2 : rb) - (ra === undefined ? -2 : ra);
                });
            } else {
                values.sort();
            }
            select.innerHTML = "";
            var all = document.createElement("option");
            all.value = "";
            all.textContent = "All";
            select.appendChild(all);
            values.forEach(function (v) {
                var option = document.createElement("option");
                option.value = v;
                option.textContent = v + " (" + counts[v] + ")";
                select.appendChild(option);
            });
            $(select).off("change.sunshine").on("change.sunshine", function () {
                var search = this.value ? "(^|, )" + escapeRegex(this.value) + "(, |$)" : "";
                api.column(columnIndex).search(search, true, false).draw();
            });
        });
    };

    window.sunshineBuildStateFilter = function () {
        window.sunshineBuildColumnDropdowns();
        var container = document.getElementById("state-filter-container");
        if (!container) { return; }
        var info = countVulnerabilities();
        container.innerHTML = "";
        if (!info) { container.style.display = "none"; return; }

        var presentOtherThanUnassigned = Object.keys(info.counts).some(function (g) { return g !== "unassigned"; });
        if (!presentOtherThanUnassigned) {
            // no analysis state declared anywhere: nothing to filter
            container.style.display = "none";
            window.sunshineApplyStateFilter();
            return;
        }
        container.style.display = "block";

        var title = document.createElement("div");
        title.innerHTML = "<b>Analysis state</b> (VEX/VDR): untick a state to hide its vulnerabilities from the tables, counters and charts. Nothing is removed from the report.";
        container.appendChild(title);

        GROUPS.forEach(function (g) {
            var count = info.counts[g.key] || 0;
            if (count === 0) { return; }
            var wrapper = document.createElement("div");
            wrapper.className = "form-check form-check-inline";
            var input = document.createElement("input");
            input.type = "checkbox";
            input.className = "form-check-input";
            input.id = "state-toggle-" + g.key;
            input.checked = active[g.key] !== false;
            input.addEventListener("change", function () {
                active[g.key] = input.checked;
                window.sunshineApplyStateFilter();
            });
            var label = document.createElement("label");
            label.className = "form-check-label";
            label.htmlFor = input.id;
            label.innerHTML = '<span class="badge state-badge state-' + g.key + '">' + g.label + " (" + count + ")</span>";
            wrapper.appendChild(input);
            wrapper.appendChild(label);
            container.appendChild(wrapper);
        });

        var note = document.createElement("div");
        note.id = "state-filter-note";
        note.className = "text-muted";
        container.appendChild(note);

        window.sunshineApplyStateFilter();
    };
})();
