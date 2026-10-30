"""A2A task lifecycle with explicit cooperative cancellation semantics."""
from __future__ import annotations
import threading,time,uuid
from .requestlimits import validate_request,RequestBudgetError
SCHEMA="pegrex.a2a-task.v1"; MAX_TIMEOUT_MS=300_000; MAX_ACTIVE_TASKS=128; MAX_RETAINED_TASKS=1024
def execute_task(handler,params,*,budget=None,timeout_ms=1000,cancel_event=None,task_id=None):
    if not isinstance(timeout_ms,int) or isinstance(timeout_ms,bool) or not 1<=timeout_ms<=MAX_TIMEOUT_MS: return {"schema":SCHEMA,"status":"unknown","task_id":task_id,"evidence":[],"partial":True,"unknowns":["invalid timeout budget"]}
    try: validate_request({"params":params,"budget":budget or {}})
    except RequestBudgetError as error: return {"schema":SCHEMA,"status":"unknown","task_id":task_id,"evidence":[],"partial":True,"unknowns":[str(error)]}
    budget=budget or {}; cancel_event=cancel_event or threading.Event(); task_id=task_id or str(uuid.uuid4()); started=time.monotonic(); deadline=started+timeout_ms/1000
    base={"schema":SCHEMA,"schema_version":1,"task_id":task_id,"budget":budget,"timeout_ms":timeout_ms,"evidence":[],"partial":False,"unknowns":[]}
    try:
        result=handler(params,budget,deadline,cancel_event)
        if not isinstance(result,dict) or "evidence" not in result: return base|{"status":"unknown","result":None,"unknowns":["task returned no evidence field"]}
        timed_out=time.monotonic()>deadline; cancelled=cancel_event.is_set(); status="timeout" if timed_out else "cancelled" if cancelled else result.get("status","completed")
        if status not in {"completed","partial","cancelled","timeout","unknown"}: status="unknown"
        return base|result|{"status":status,"partial":bool(result.get("partial")) or status in {"timeout","cancelled","partial"},"elapsed_ms":round((time.monotonic()-started)*1000,3),"execution_active":False,"cancellation":"cooperative-only"}
    except Exception as error: return base|{"status":"unknown","partial":True,"result":getattr(error,"partial",None),"unknowns":[f"task error: {type(error).__name__}"],"elapsed_ms":round((time.monotonic()-started)*1000,3),"execution_active":False,"cancellation":"cooperative-only"}
class A2ATaskProtocol:
    def __init__(self): self.tasks={}; self.handlers={}; self.lock=threading.Lock()
    def register(self,method,handler):
        if not isinstance(method,str) or not method or not callable(handler): raise ValueError("method and callable handler are required")
        self.handlers[method]=handler
    def submit(self,method,params,*,budget=None,timeout_ms=1000):
        if method not in self.handlers: return {"status":"unknown","unknowns":["unregistered task method"]}
        if not isinstance(timeout_ms,int) or isinstance(timeout_ms,bool) or not 1<=timeout_ms<=MAX_TIMEOUT_MS: return {"status":"unknown","unknowns":["invalid timeout budget"]}
        try: validate_request({"params":params,"budget":budget or {}})
        except RequestBudgetError as error: return {"status":"unknown","unknowns":[str(error)]}
        task_id=str(uuid.uuid4()); cancel=threading.Event()
        with self.lock:
            if sum(bool(t.get("execution_active")) for t in self.tasks.values())>=MAX_ACTIVE_TASKS: return {"status":"unknown","unknowns":["active task limit exceeded"]}
            if len(self.tasks)>=MAX_RETAINED_TASKS:
                for old_id in list(self.tasks):
                    if not self.tasks[old_id].get("execution_active"):
                        del self.tasks[old_id]
                        if len(self.tasks)<MAX_RETAINED_TASKS: break
            if len(self.tasks)>=MAX_RETAINED_TASKS: return {"status":"unknown","unknowns":["retained task limit exceeded"]}
            self.tasks[task_id]={"schema":SCHEMA,"schema_version":1,"task_id":task_id,"status":"running","cancel":cancel,"execution_active":True,"timeout_ms":timeout_ms,"cancellation":"cooperative-only"}
        def mark_timeout():
            cancel.set()
            with self.lock:
                task=self.tasks.get(task_id)
                if task and task.get("execution_active"):
                    task["status"]="timeout-running"; task["cancellation"]="requested; handler may still be executing"
        timer=threading.Timer(timeout_ms/1000,mark_timeout); timer.daemon=True; timer.start()
        def work():
            result=execute_task(self.handlers[method],params,budget=budget,timeout_ms=timeout_ms,cancel_event=cancel,task_id=task_id); timer.cancel()
            with self.lock: self.tasks[task_id].update(result,execution_active=False); self.tasks[task_id].pop("cancel",None)
        threading.Thread(target=work,daemon=True,name=f"pegrex-a2a-{task_id[:8]}").start()
        return {"schema":SCHEMA,"schema_version":1,"task_id":task_id,"status":"running","budget":budget or {},"timeout_ms":timeout_ms,"cancellation":"cooperative-only"}
    def cancel(self,task_id):
        with self.lock:
            task=self.tasks.get(task_id)
            if not task: return {"status":"unknown","unknowns":["unknown task"]}
            task["cancel"].set()
            if task["execution_active"]: task["status"]="cancellation-requested"; task["cancellation"]="requested; handler may still be executing"
            return {"task_id":task_id,"status":task["status"],"execution_active":task["execution_active"],"cancellation":task.get("cancellation","cooperative-only")}
    def status(self,task_id):
        with self.lock:
            task=self.tasks.get(task_id)
            if not task: return {"status":"unknown","unknowns":["unknown task"]}
            return {k:v for k,v in task.items() if k!="cancel"}
    def handle(self,message):
        params=message.get("params") or {}; method=message.get("method"); mid=message.get("id")
        try:
            if method=="task.submit": result=self.submit(params["operation"],params.get("input") or {},budget=params.get("budget"),timeout_ms=params.get("timeout_ms",1000))
            elif method=="task.cancel": result=self.cancel(params["task_id"])
            elif method in {"task.status","task.result"}: result=self.status(params["task_id"])
            else: return {"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"unknown task method"}}
            return {"jsonrpc":"2.0","id":mid,"result":result}
        except (KeyError,TypeError,ValueError): return {"jsonrpc":"2.0","id":mid,"error":{"code":-32602,"message":"invalid task request"}}
