from models import ConfigAction, ROPTest
from config import load_protection_config
import csv
import yaml
import os

from tests import Ret2WinTest, Ret2LibcShellTest

TESTS: list[ROPTest] = [
    Ret2WinTest("./bin/ret2win"),
    Ret2LibcShellTest("./bin/overflow")
]

def run_tests(config_file):

    results = []

    protections = load_protection_config(config_file)
    selected_actions = [protections["disable-aslr"], protections["disable-canary"]]

    for test in TESTS:
        result = test.run_test(selected_actions)
        results.append(result)

    if not os.path.exists("results"):
        os.mkdir("results")

    with open(f"results/{config_file}_results.yaml", "w") as yamlfile:
        yaml.dump(selected_actions, yamlfile)

    with open(f"results/{config_file}_results.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Test Name", "Attack Successful"])
        for result in results:
            writer.writerow([result["name"], result["attack_succeeded"]])

    return results

if __name__ == "__main__":
    results = run_tests("actions.yaml")