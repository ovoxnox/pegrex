import json

from pegrex.export import to_sarif
from pegrex.flow import (
    SinkRule, SourceRule, analyze_modules, analyze_secrets, analyze_source,
)

USER = (SourceRule("user", r"user_input", category="user-input"),)
EVAL = (SinkRule("eval", r"eval", sanitizers=(r"is_safe|sanitize",)),)


def test_cfg_fixed_point_and_path_sensitive_sanitizer():
    result = analyze_source("""def f():
    x = user_input()
    if is_safe(x):
        eval(x)
    else:
        eval(x)
""", source_rules=USER, sink_rules=EVAL, report_parameters=False)
    assert result["fixed_point"]["stable"]
    assert len(result["findings"]) == 1
    assert result["findings"][0]["line"] == 6


def test_loop_reaches_fixed_point_without_losing_flow():
    result = analyze_source("""def f(n):
    x = user_input()
    while n:
        x = x
    eval(x)
""", source_rules=USER, sink_rules=EVAL, report_parameters=False)
    assert result["fixed_point"]["stable"]
    assert len(result["findings"]) == 1


def test_cross_module_summary_instantiates_only_tainted_actual():
    result = analyze_modules({
        "app": ("app.py", "from helper import check\n\ndef run():\n    check('constant')\n    check(user_input())\n"),
        "helper": ("helper.py", "def check(value):\n    eval(value)\n"),
    }, source_rules=USER, sink_rules=EVAL)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["file"] == "app.py"
    assert result["summaries"]["helper.check"]["parameters"] == ["value"]


def test_context_sensitive_sink_keywords_states_and_manager():
    rules = (SinkRule("execute", r"execute", sanitizers=(r"clean",),
                      safe_keywords=(("mode", "safe"),),
                      safe_state_arguments=((1, ("trusted",)),),
                      safe_contexts=(r"trusted_connection",)),)
    result = analyze_source("""def f():
    value = user_input()
    execute(value, mode='safe')
    execute(value, 'trusted')
    with trusted_connection():
        execute(value)
    execute(value)
""", source_rules=USER, sink_rules=rules, report_parameters=False)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["line"] == 7


def test_secret_flow_categories_and_redaction():
    result = analyze_secrets("""password = 'value'
print(password)
print(mask_secret(password))
token = read_token()
logger.info(token)
subprocess.run([token])
""")
    categories = {row["category"] for row in result["findings"]}
    assert "log" in categories
    assert "process-arguments" in categories
    lines = [row["line"] for row in result["findings"] if row["category"] == "log"]
    assert lines.count(2) == 1
    assert 3 not in lines


def test_recursion_is_widened_and_not_silent():
    result = analyze_source("""def f(value):
    if value:
        return f(value)
    return value
""", source_rules=USER, sink_rules=EVAL)
    assert result["fixed_point"]["stable"]
    assert "memory.f" in result["fixed_point"]["widened"]
    assert any("widened" in row for row in result["summaries"]["memory.f"]["unknowns"])


def test_flow_findings_export_sarif_source_sink_code_flow():
    result = analyze_source("def f():\n    value = user_input()\n    eval(value)\n",
                            source_rules=USER, sink_rules=EVAL, report_parameters=False)
    sarif = json.loads(to_sarif(result["findings"]))
    row = sarif["runs"][0]["results"][0]
    assert row["relatedLocations"][0]["physicalLocation"]["region"]["startLine"] == 2
    assert row["codeFlows"][0]["threadFlows"][0]["locations"][0]["kinds"] == ["source"]
    assert row["properties"]["category"] == "injection"
