from pegrex.concurrency_analysis import analyze_concurrency


RACE = '''
import threading
value = 0
lock = threading.Lock()

def worker():
    global value
    value += 1

threading.Thread(target=worker)
'''


def test_shared_write_without_common_lock_is_possible_race():
    report = analyze_concurrency(RACE)
    races = [row for row in report["findings"] if row["kind"] == "race"]
    assert races and races[0]["verdict"] == "possible"
    assert races[0]["evidence"]["variable"] == "value"
    assert report["status"] == "unknown"  # alias/happens-before is approximate


def test_common_lock_suppresses_race_candidate_but_not_coverage():
    source = RACE.replace("value += 1", "with lock:\n        value += 1")
    report = analyze_concurrency(source)
    assert not [row for row in report["findings"] if row["kind"] == "race"]
    assert any(row["kind"] == "interference" for row in report["findings"])


def test_lock_order_cycle_is_deadlock_evidence():
    source = '''
import threading
threading.Thread(target=first)
threading.Thread(target=second)
def first():
    with lock_a:
        with lock_b:
            pass
def second():
    with lock_b:
        with lock_a:
            pass
'''
    report = analyze_concurrency(source)
    deadlocks = [row for row in report["findings"] if row["kind"] == "deadlock"]
    assert deadlocks
    assert deadlocks[0]["evidence"]["lock_cycle"] == ["lock_a", "lock_b", "lock_a"]


def test_relaxed_atomic_is_selected_memory_ordering_evidence():
    report = analyze_concurrency(
        "#include <atomic>\nstd::atomic<int> x; void f(){x.load(std::memory_order_relaxed);}", "c")
    assert report["memory_ordering"][0]["evidence"]["property"] == "relaxed-atomic"
    assert report["findings"][0]["verdict"] == "possible"
