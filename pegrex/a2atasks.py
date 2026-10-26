"""A2A task lifecycle with budgets, deadlines, cancellation, and partial evidence."""
from __future__ import annotations
import threading,time,uuid
SCHEMA="pegrex.a2a-task.v1"

def execute_task(handler,params,*,budget=None,timeout_ms=1000,cancel_event=None,task_id=None):
    """Implement execute task with the module's explicit API and failure semantics."""
    budget=budget or {};cancel_event=cancel_event or threading.Event();task_id=task_id or str(uuid.uuid4())
    started=time.monotonic();deadline=started+timeout_ms/1000
    base={"schema":SCHEMA,"schema_version":1,"task_id":task_id,"budget":budget,
          "timeout_ms":timeout_ms,"evidence":[],"partial":False,"unknowns":[]}
    try:
        result=handler(params,budget,deadline,cancel_event)
        if not isinstance(result,dict) or "evidence" not in result:
            return base|{"status":"unknown","result":result,"unknowns":["task returned no evidence field"]}
        timed_out=time.monotonic()>deadline;cancelled=cancel_event.is_set()
        status="timeout" if timed_out else "cancelled" if cancelled else result.get("status","completed")
        if status not in {"completed","partial","cancelled","timeout","unknown"}:status="unknown"
        return base|result|{"status":status,"partial":bool(result.get("partial")) or status in {"timeout","cancelled","partial"},
                            "elapsed_ms":round((time.monotonic()-started)*1000,3)}
    except Exception as error:
        return base|{"status":"unknown","partial":True,"result":getattr(error,"partial",None),
                     "unknowns":[f"task error: {type(error).__name__}: {error}"]}

class A2ATaskProtocol:
    def __init__(self):self.tasks={};self.handlers={};self.lock=threading.Lock()
    def register(self, method, handler):
        """Implement register with explicit API and failure semantics."""
        self.handlers[method] = handler
    def submit(self,method,params,*,budget=None,timeout_ms=1000):
        """Implement submit with the module's explicit API and failure semantics."""
        if method not in self.handlers:return {"status":"unknown","unknowns":["unregistered task method"]}
        task_id=str(uuid.uuid4());cancel=threading.Event()
        with self.lock:self.tasks[task_id]={"status":"running","cancel":cancel,"execution_active":True}
        def work():
            """Implement work with the module's explicit API and failure semantics."""
            result=execute_task(self.handlers[method],params,budget=budget,timeout_ms=timeout_ms,cancel_event=cancel,task_id=task_id)
            with self.lock:self.tasks[task_id].update(result,execution_active=False)
        threading.Thread(target=work,daemon=True).start()
        return {"schema":SCHEMA,"schema_version":1,"task_id":task_id,"status":"running","budget":budget or {},"timeout_ms":timeout_ms}
    def cancel(self,task_id):
        """Implement cancel with the module's explicit API and failure semantics."""
        with self.lock:
            task=self.tasks.get(task_id)
            if not task:return {"status":"unknown","unknowns":["unknown task"]}
            task["cancel"].set()
            if task["status"]=="running":task["status"]="cancellation-requested"
            return {"task_id":task_id,"status":task["status"],"execution_active":task["execution_active"]}
    def status(self,task_id):
        """Implement status with the module's explicit API and failure semantics."""
        with self.lock:
            task=self.tasks.get(task_id)
            if not task:return {"status":"unknown","unknowns":["unknown task"]}
            return {k:v for k,v in task.items() if k!="cancel"}
    def handle(self,message):
        """Implement handle with the module's explicit API and failure semantics."""
        params=message.get("params") or {};method=message.get("method");mid=message.get("id")
        try:
            if method=="task.submit":result=self.submit(params["operation"],params.get("input") or {},budget=params.get("budget"),timeout_ms=params.get("timeout_ms",1000))
            elif method=="task.cancel":result=self.cancel(params["task_id"])
            elif method in {"task.status","task.result"}:result=self.status(params["task_id"])
            else:return {"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"unknown task method"}}
            return {"jsonrpc":"2.0","id":mid,"result":result}
        except (KeyError,TypeError,ValueError) as error:return {"jsonrpc":"2.0","id":mid,"error":{"code":-32602,"message":str(error)}}
