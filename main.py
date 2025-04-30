from models import ConfigAction, ROPTest
from config import load_protection_config
from pathlib import Path

from tests import Ret2WinTest, Ret2LibcShellTest, FormatStringBypassCanaryTest

from results import write_results_to_yaml, write_results_to_csv

TESTS: list[ROPTest] = [
    Ret2WinTest("./bin/ret2win"),
    Ret2LibcShellTest("./bin/overflow"),
    FormatStringBypassCanaryTest("./bin/coalmine"),
]

def run_tests(run_id: str, config_file: str | Path):

    results = []

    available_protections = load_protection_config(config_file)
    #selected_actions = [protections["disable-aslr"], protections["disable-canary"]] # show everything works?
    selected_actions = [available_protections["disable-aslr"]] # canary testing
    #selected_actions = [] # show everything fails

    for test in TESTS:
        result = test.run_test(selected_actions)
        results.append(result)

    write_results_to_csv(run_id, results)
    write_results_to_yaml(run_id, selected_actions, TESTS, results)

    return results

if __name__ == "__main__":
    results = run_tests("test_run", "actions.yaml")