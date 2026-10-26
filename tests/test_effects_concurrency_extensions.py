from pegrex.concurrency_analysis import analyze_concurrency
from pegrex.effects import CATEGORIES, infer_effects, transitive_effects


def test_process_launch_is_explicit_and_transitive():
    direct = infer_effects("""import subprocess
def launch():
    return subprocess.run(['tool'])
def caller():
    return launch()
""")["functions"]
    assert "process" in CATEGORIES
    assert "process" in direct["launch"]["categories"]
    result = transitive_effects(direct, {"caller": ["launch"], "launch": []})
    row = next(row for row in result["caller"]["effects"] if row["category"] == "process")
    assert row["origin"] == "inherited:launch"


def test_explicit_happens_before_edges_for_threads_futures_and_async():
    report = analyze_concurrency("""import threading, asyncio
value = 0
def worker():
    global value
    value += 1
thread = threading.Thread(target=worker)
thread.start()
thread.join()
future = executor.submit(worker)
future.result()
async def run():
    task = asyncio.create_task(worker())
    await task
""")
    kinds = {row["kind"] for row in report["happens_before"]["edges"]}
    assert {"thread-start", "thread-join", "future-result", "async-await"} <= kinds
    assert any(row["task"] == "future" for row in report["happens_before"]["tasks"])
    assert "alias coverage partial" in report["coverage"]["happens_before"]
