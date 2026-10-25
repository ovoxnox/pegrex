"""Optional process concurrency is deterministic and benchmarkable."""
import json
import pathlib
import subprocess
import sys

from pegrex.concurrency import benchmark_process_map, callgraph_worker, process_map


def test_small_repositories_stay_sequential(monkeypatch, tmp_path):
    source = tmp_path / "a.py"
    source.write_text("def f():\n    return 1\n")
    monkeypatch.setattr("pegrex.concurrency.mp.get_context",
                        lambda *_: (_ for _ in ()).throw(AssertionError("unexpected pool")))
    result = process_map(callgraph_worker, [(str(source), "python")], workers=4)
    assert list(result[0][1].functions) == ["f"]


def test_spawn_workers_and_benchmark_match_sequential(tmp_path):
    tasks = []
    for name in ("a.py", "b.py"):
        path = tmp_path / name
        path.write_text(f"def {path.stem}():\n    return 1\n")
        tasks.append((str(path), "python"))
    result = process_map(callgraph_worker, tasks, workers=2, min_parallel=1)
    assert [set(graph.functions) for _, graph in result] == [{"a"}, {"b"}]
    report = benchmark_process_map(callgraph_worker, tasks[:1], workers=2)
    assert report["context"] == "spawn"
    assert report["results_equal"] is True
    assert report["items"] == 1
    assert report["overhead_seconds"] == (
        report["parallel_seconds"] - report["sequential_seconds"])


def test_directory_callgraph_cli_opt_in_and_benchmark(tmp_path):
    (tmp_path / "a.py").write_text("def a():\n    return 1\n")
    command = [sys.executable, "-m", "pegrex.cli", "callgraph", "--dir", str(tmp_path),
               "--jobs", "2", "--benchmark", "--ascii"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "a.a (leaf)" in result.stdout
    benchmark = json.loads(result.stderr)["callgraph_benchmark"]
    assert benchmark["results_equal"] is True
