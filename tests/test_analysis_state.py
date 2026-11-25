import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sunshine  # noqa: E402


def parse(bom):
    return sunshine.parse_json_data(bom, False, False, False, False, False, False, 0.0, 0.0)


def make_bom(analyses):
    """analyses: list of analysis objects (or None); one vulnerability per entry, all affecting component 'a'."""
    vulns = []
    for index, analysis in enumerate(analyses):
        vuln = {"id": f"CVE-2024-{1000 + index}",
                "ratings": [{"severity": "high", "score": 7.5, "method": "CVSSv31"}],
                "affects": [{"ref": "a"}]}
        if analysis is not None:
            vuln["analysis"] = analysis
        vulns.append(vuln)
    return {"bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"type": "library", "name": "a", "version": "1", "bom-ref": "a"}],
            "vulnerabilities": vulns}


def test_parse_analysis_defaults_to_unassigned():
    assert sunshine.parse_analysis({})["state"] == "unassigned"
    assert sunshine.parse_analysis({"analysis": {}})["state"] == "unassigned"


def test_parse_analysis_reads_all_fields():
    analysis = sunshine.parse_analysis({"analysis": {"state": "not_affected",
                                                     "justification": "code_not_reachable",
                                                     "response": ["will_not_fix"],
                                                     "detail": "d",
                                                     "firstIssued": "2024-01-01T00:00:00Z",
                                                     "lastUpdated": "2024-02-01T00:00:00Z"}})
    assert analysis == {"state": "not_affected", "justification": "code_not_reachable", "response": ["will_not_fix"],
                        "detail": "d", "first_issued": "2024-01-01T00:00:00Z", "last_updated": "2024-02-01T00:00:00Z"}


def test_state_groups():
    assert sunshine.get_state_group("resolved") == "resolved"
    assert sunshine.get_state_group("resolved_with_pedigree") == "resolved"
    assert sunshine.get_state_group("something_new") == "other"


def test_nothing_is_dropped_by_state():
    states = ["exploitable", "in_triage", "resolved", "resolved_with_pedigree", "false_positive", "not_affected"]
    components, _ = parse(make_bom([{"state": s} for s in states] + [None]))
    vulns = components["a"]["vulnerabilities"]
    assert len(vulns) == len(states) + 1
    assert {v["analysis"]["state"] for v in vulns} == set(states) | {"unassigned"}


def test_vulnerability_table_is_annotated_with_state_groups():
    components, _ = parse(make_bom([{"state": "not_affected", "justification": "code_not_present"}]))
    vulnerabilities, *_ = sunshine.parse_vulnerabilities(components, False)
    table, _, _ = sunshine.build_vulnerabilities_table_content(vulnerabilities, components)
    assert 'data-states="not_affected"' in table
    assert 'data-sev="high"' in table
    assert "code_not_present" in table


def test_same_cve_different_state_per_component():
    bom = make_bom([None])
    bom["components"].append({"type": "library", "name": "b", "version": "1", "bom-ref": "b"})
    other = dict(bom["vulnerabilities"][0])
    other["affects"] = [{"ref": "b"}]
    other["analysis"] = {"state": "resolved"}
    bom["vulnerabilities"].append(other)
    components, _ = parse(bom)
    vulnerabilities, *_ = sunshine.parse_vulnerabilities(components, False)
    assert len(vulnerabilities) == 1
    entry = next(iter(vulnerabilities.values()))
    assert entry["direct_groups"] == {"a": {"unassigned"}, "b": {"resolved"}}


def test_chart_nodes_carry_state_pairs():
    components, _ = parse(make_bom([{"state": "false_positive"}]))
    data = sunshine.build_echarts_data(components)
    assert data[0]["dv"] == [["high", "false_positive"]]
    assert data[0]["tv"] == []
    assert 'data-state="false_positive"' in data[0]["name"]


def test_components_table_state_segment():
    components, _ = parse(make_bom([{"state": "not_affected"}, None]))
    table = sunshine.build_components_table_content(components)
    assert "&#x2192; CVE-2024-1000 &#x2192; not_affected" in table
    assert "CVE-2024-1001</span>" in table  # unassigned: no third segment


def test_vulnerabilities_table_dropdowns():
    components, _ = parse(make_bom([{"state": "not_affected"}]))
    vulnerabilities, *_ = sunshine.parse_vulnerabilities(components, False)
    table, _, _ = sunshine.build_vulnerabilities_table_content(vulnerabilities, components)
    for name in ("severity", "state", "justification"):
        assert f'<select class="form-select search-select" data-filter="{name}">' in table
    assert 'placeholder="Search Response"' in table
