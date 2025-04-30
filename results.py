import os
import csv
import yaml
from models import TestResult, ROPTest, ConfigAction

RESULTS_FOLDER = "results"
    
def get_results_folder() -> str:
    if not os.path.exists(RESULTS_FOLDER):
        os.mkdir(RESULTS_FOLDER)
    return RESULTS_FOLDER

def write_results_to_yaml(run_id: str, environment: list[ConfigAction], tests: list[ROPTest], results: list[TestResult]):
    """
    Writes metadata and results of a test run to a YAML file.

    Args:
        run_id (str): The unique identifier for the test run.
        environment (list[ConfigAction]): A list of ConfigAction objects representing the environment.
        test_outcomes (list[tuple[ROPTest, TestResult]]): A list of tuples containing ROPTest and TestResult objects.
    """
    filename = os.path.join(get_results_folder(), f"{run_id}_results.yaml")
    with open(filename, 'w') as file:
        yaml.dump({
            "run_id": run_id,
            "environment": [action.__dict__ for action in environment],
            "tests": [test.__dict__ for test in tests],
            "results": [outcome.__dict__ for outcome in results]
        }, file)

def write_results_to_csv(run_id: str, results: list[TestResult]):
    """
    Writes test results to a CSV file.

    Args:
        run_id (str): The unique identifier for the test run.
        results (list[TestResult]): A list of TestResult objects containing the test results.
    """
    filename = os.path.join(get_results_folder(), f"{run_id}_results.csv")
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(TestResult.get_header())
        writer.writerows([result.to_tuple() for result in results])