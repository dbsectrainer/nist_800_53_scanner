import json
from datetime import datetime, timedelta, timezone

import pytest

from engine.collectors.base import Collector
from engine.coverage import control_rollup, load_catalog_ids, summarize
from engine.evaluate import evaluate_all
from engine.expr import ExpressionError, evaluate
from engine.models import AssessmentRun, Evidence, Status
from engine.oscal import to_assessment_results, to_poam
from engine.rules import Policy, RuleError, load_rules, parse_rule
from engine.runner import ROOT, run_assessment

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def rule(**kw):
    base = {
        "rule_id": "T-1", "control": "AC-2", "title": "t", "method": "test",
        "parameters": {"limit": 2},
        "evidence": {"type": "x.y", "required_fields": ["n"]},
        "condition": "n <= limit", "observed": "{n} vs {limit}", "remediation": "fix",
    }
    base.update(kw)
    return parse_rule(base)


def ev(payload, age_hours=0, asset="a1"):
    return Evidence(type="x.y", asset_id="a1" if asset is None else asset, collector="c",
                    payload=payload, collected_at=NOW - timedelta(hours=age_hours))


def run_with(rules, evidence=(), errors=(), policy=None):
    run = AssessmentRun(system_id="sys", evidence=list(evidence), errors=list(errors))
    return evaluate_all(run, rules, policy or Policy(), now=NOW)


# --- expression safety -------------------------------------------------
@pytest.mark.parametrize("bad", [
    "__import__('os').system('x')", "().__class__", "open('f')", "[x for x in y for z in w]",
    "lambda: 1", "a.b",
])
def test_unsafe_expressions_rejected(bad):
    with pytest.raises(ExpressionError):
        evaluate(bad, {"y": [1], "w": [1], "a": 1}, NOW)


def test_expression_basics():
    assert evaluate("len([a for a in xs if a > 1]) == 2", {"xs": [1, 2, 3]}, NOW)
    assert evaluate("age_days(ts) > 1", {"ts": NOW.timestamp() - 3 * 86400}, NOW)
    assert evaluate("x is None or x > 1", {"x": None}, NOW)


# --- statuses ----------------------------------------------------------
def test_satisfied_and_other_than_satisfied():
    out = run_with([rule()], [ev({"n": 1}, asset="ok"), ev({"n": 5}, asset="bad")]).assessments
    by = {a.asset_id: a for a in out}
    assert by["ok"].status == Status.SATISFIED
    assert by["bad"].status == Status.OTHER_THAN_SATISFIED
    assert by["bad"].observed == "5 vs 2"


def test_missing_evidence_is_not_assessed():
    a = run_with([rule()]).assessments[0]
    assert a.status == Status.NOT_ASSESSED and "no evidence" in a.reason


def test_stale_evidence_is_not_assessed():
    a = run_with([rule()], [ev({"n": 1}, age_hours=48)]).assessments[0]
    assert a.status == Status.NOT_ASSESSED and "stale" in a.reason


def test_missing_required_field_is_not_assessed():
    a = run_with([rule()], [ev({"other": 1})]).assessments[0]
    assert a.status == Status.NOT_ASSESSED


def test_collector_error_is_not_assessed_not_pass():
    class Boom(Collector):
        name, evidence_type = "boom", "x.y"

        def gather(self):
            raise ConnectionError("unreachable")

    evidence, errors = Boom().collect()
    assert not evidence and errors
    a = run_with([rule()], evidence, errors).assessments[0]
    assert a.status == Status.NOT_ASSESSED and "unreachable" in a.reason


def test_error_for_one_asset_not_hidden_by_other_asset_pass():
    from engine.models import CollectionError
    out = run_with([rule()], [ev({"n": 1})], [CollectionError("c", "x.y", "creds expired", "a2")]).assessments
    assert {a.status for a in out} == {Status.SATISFIED, Status.NOT_ASSESSED}


def test_unevaluable_condition_is_not_assessed():
    a = run_with([rule(condition="n['k'] > 1")], [ev({"n": 1})]).assessments[0]
    assert a.status == Status.NOT_ASSESSED


def test_manual_method_never_automated_pass():
    a = run_with([rule(method="interview", condition=None)], [ev({"n": 1})]).assessments[0]
    assert a.status == Status.NOT_ASSESSED and "assessor" in a.reason


def test_applicable_when_and_documented_na():
    a = run_with([rule(applicable_when="n > 100")], [ev({"n": 1})]).assessments[0]
    assert a.status == Status.NOT_APPLICABLE
    pol = Policy(not_applicable=[{"control": "AC-2", "rationale": "none", "decided_by": "assessor"}])
    assert run_with([rule()], [ev({"n": 9})], policy=pol).assessments[0].status == Status.NOT_APPLICABLE
    incomplete = Policy(not_applicable=[{"control": "AC-2", "rationale": "none"}])
    assert run_with([rule()], [ev({"n": 9})], policy=incomplete).assessments[0].status == Status.OTHER_THAN_SATISFIED


# --- parameters and exceptions ----------------------------------------
def test_parameter_inheritance():
    pol = Policy(global_params={"limit": 10}, system_params={"sys": {"limit": 1}})
    assert run_with([rule()], [ev({"n": 5})], policy=Policy(global_params={"limit": 10})).assessments[0].status == Status.SATISFIED
    assert run_with([rule()], [ev({"n": 5})], policy=pol).assessments[0].status == Status.OTHER_THAN_SATISFIED


def test_exception_recorded_but_not_hidden_and_expiry_enforced():
    good = {"rule_id": "T-1", "owner": "o", "approved_by": "ao", "expires": "2027-01-01"}
    a = run_with([rule()], [ev({"n": 9})], policy=Policy(exceptions=[good])).assessments[0]
    assert a.status == Status.OTHER_THAN_SATISFIED and a.exception
    expired = {**good, "expires": "2026-01-01"}
    a = run_with([rule()], [ev({"n": 9})], policy=Policy(exceptions=[expired])).assessments[0]
    assert a.exception is None and "expired" in a.reason
    no_approver = {k: v for k, v in good.items() if k != "approved_by"}
    assert run_with([rule()], [ev({"n": 9})], policy=Policy(exceptions=[no_approver])).assessments[0].exception is None


# --- rules loading -----------------------------------------------------
def test_rule_validation():
    with pytest.raises(RuleError):
        parse_rule({"rule_id": "x"})
    with pytest.raises(RuleError):
        rule(condition="__import__('os')")
    with pytest.raises(RuleError):
        rule(method="guess")


def test_shipped_rules_load():
    rules = load_rules(f"{ROOT}/rules")
    assert len({r.rule_id for r in rules}) == len(rules) >= 10


# --- coverage + oscal ---------------------------------------------------
def test_catalog_controls_without_rules_are_not_assessed(tmp_path):
    cat = tmp_path / "cat.json"
    cat.write_text(json.dumps({"catalog": {"groups": [{"controls": [
        {"id": "ac-2", "controls": [{"id": "ac-2.1"}]}, {"id": "pe-1"}]}]}}))
    assert load_catalog_ids(str(cat)) == ["AC-2", "AC-2.1", "PE-1"]
    run = run_with([rule()], [ev({"n": 1})])
    run.catalog_controls = load_catalog_ids(str(cat))
    roll = control_rollup(run)
    assert roll["AC-2"] == Status.SATISFIED
    assert roll["PE-1"] == Status.NOT_ASSESSED
    s = summarize(run)
    assert s["controls_total"] == 3 and s["controls_assessed"] == 1


def test_rollup_worst_wins():
    run = run_with([rule(), rule(rule_id="T-2", method="interview", condition=None)], [ev({"n": 1})])
    assert control_rollup(run)["AC-2"] == Status.NOT_ASSESSED
    run = run_with([rule(), rule(rule_id="T-2")], [ev({"n": 1}), ev({"n": 9}, asset="b")])
    assert control_rollup(run)["AC-2"] == Status.OTHER_THAN_SATISFIED


def test_oscal_output_structure():
    run = run_with([rule(), rule(rule_id="T-2", method="interview", condition=None)], [ev({"n": 9})])
    ar = to_assessment_results(run)["assessment-results"]
    res = ar["results"][0]
    assert ar["metadata"]["oscal-version"] and len(res["observations"]) == 1
    states = {f["props"][0]["value"]: f["target"]["status"] for f in res["findings"]}
    assert states["other_than_satisfied"]["state"] == "not-satisfied"
    na = [f for f in res["findings"] if f["props"][0]["value"] == "not_assessed"][0]
    assert na["target"]["status"]["reason"]  # not-assessed carries an explicit reason
    assert res["observations"][0]["uuid"] == res["findings"][0]["related-observations"][0]["observation-uuid"]
    poam = to_poam(run)["plan-of-action-and-milestones"]["poam-items"]
    assert len(poam) == 1  # only other_than_satisfied becomes a POA&M item


def test_end_to_end_unreachable_collectors_do_not_inflate(tmp_path):
    class Dead(Collector):
        name, evidence_type = "dead", "linux.accounts"

        def gather(self):
            raise RuntimeError("down")

    run = run_assessment({}, collectors=[Dead()])
    assert not any(a.status == Status.SATISFIED for a in run.assessments)
    assert run.errors
    assert summarize(run)["objective_counts"].get("satisfied", 0) == 0


# --- OSCAL schema validation (offline copies of the NIST 1.1.2 schemas) ---
def _validator(name):
    jsonschema = pytest.importorskip("jsonschema")
    regex = pytest.importorskip("regex")  # OSCAL patterns use \p{...}
    import jsonschema._keywords as keywords
    keywords.re = regex
    import os
    path = os.path.join(os.path.dirname(__file__), "schemas", name)
    with open(path) as fh:
        return jsonschema.Draft7Validator(json.load(fh))


def test_oscal_outputs_validate_against_nist_schema():
    stale = ev({"n": 9}, age_hours=99, asset="stale")
    run = run_with([rule(), rule(rule_id="T-2", method="interview", condition=None)],
                   [ev({"n": 9}), ev({"n": 1}, asset="b"), stale])
    exc_policy = Policy(not_applicable=[{"rule_id": "T-1", "asset_id": "c", "rationale": "r", "decided_by": "d"}])
    run2 = run_with([rule()], [ev({"n": 1}, asset="c")], policy=exc_policy)
    for r in (run, run2, run_with([rule()])):
        errs = list(_validator("oscal_assessment-results_schema_1.1.2.json").iter_errors(to_assessment_results(r)))
        assert not errs, errs[0].message
        poam = to_poam(r)
        if poam["plan-of-action-and-milestones"]["poam-items"]:  # schema forbids an empty list
            errs = list(_validator("oscal_poam_schema_1.1.2.json").iter_errors(poam))
            assert not errs, errs[0].message
