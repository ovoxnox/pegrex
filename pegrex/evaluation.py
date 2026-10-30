"""Labeled security-detection evaluation; metrics are evidence, not a guarantee."""
VALID_LABELS={"vulnerable","fixed"}; SEVERITIES={"critical","high","medium","low","info"}
def _validate_cases(cases):
    if not isinstance(cases,list): raise TypeError("cases must be a list")
    result={}
    for row in cases:
        if not isinstance(row,dict) or not isinstance(row.get("id"),str) or row.get("label") not in VALID_LABELS: raise ValueError("each case requires an id and vulnerable/fixed label")
        if row["id"] in result: raise ValueError("duplicate case id")
        if row.get("expected_severity") is not None and row["expected_severity"] not in SEVERITIES: raise ValueError("unsupported expected severity")
        result[row["id"]]=row
    return result
def _validate_predictions(predictions,cases):
    if not isinstance(predictions,list): raise TypeError("predictions must be a list")
    result={}
    for row in predictions:
        if not isinstance(row,dict) or row.get("id") not in cases: raise ValueError("prediction references an unknown case")
        key=row["id"]
        if key in result: raise ValueError("duplicate prediction id")
        if not isinstance(row.get("analyzed",False),bool) or not isinstance(row.get("finding",False),bool): raise ValueError("analyzed and finding must be booleans")
        if row.get("finding",False) and row.get("severity") not in SEVERITIES: raise ValueError("findings require a recognized severity")
        result[key]=row
    return result
def _ratio(a,b): return a/b if b else None
def evaluate_security_predictions(cases,predictions):
    """Measure precision, recall, F1, coverage and severity calibration.

    Unanalyzed cases are uncovered/UNKNOWN, never silently considered clean.
    """
    case_map=_validate_cases(cases); pred_map=_validate_predictions(predictions,case_map)
    tp=fp=fn=tn=covered=sev_n=sev_ok=0; uncovered=[]
    for key,case in case_map.items():
        pred=pred_map.get(key)
        if pred is None or not pred.get("analyzed",False): uncovered.append(key); continue
        covered+=1; found=pred.get("finding",False); vuln=case["label"]=="vulnerable"
        if vuln and found: tp+=1
        elif not vuln and found: fp+=1
        elif vuln: fn+=1
        else: tn+=1
        expected=case.get("expected_severity")
        if found and expected is not None: sev_n+=1; sev_ok+=pred.get("severity")==expected
    precision=_ratio(tp,tp+fp); recall=_ratio(tp,tp+fn)
    f1=2*precision*recall/(precision+recall) if precision is not None and recall is not None and precision+recall else None
    return {"schema":"pegrex.security-evaluation.v1","verdict":"unknown" if uncovered else "measured",
      "metrics":{"tp":tp,"fp":fp,"fn":fn,"tn":tn,"precision":precision,"recall":recall,"f1":f1,"coverage":_ratio(covered,len(case_map)) if case_map else 1.0,"severity_calibration":_ratio(sev_ok,sev_n),"severity_samples":sev_n},
      "cases":len(case_map),"covered":covered,"uncovered_case_ids":sorted(uncovered),
      "limitations":["metrics apply only to supplied labeled cases","uncovered cases are unknown, not clean","metrics do not prove analyzer soundness"]}
