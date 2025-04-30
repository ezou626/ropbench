import subprocess
from pwn import *

class ConfigAction:
    def __init__(self, name: str, set_cmd: str, cleanup_cmd: str):
        self.name = name
        self.set_cmd = set_cmd
        self.cleanup_cmd = cleanup_cmd

    def run(self):
        subprocess.run(self.set_cmd, shell=True, check=True)

    def cleanup(self):
        subprocess.run(self.cleanup_cmd, shell=True, check=True)

class TestResult:
    def __init__(self, name: str, result: float, message: str = ""):
        self.name = name
        self.result = result
        self.message = message

    @staticmethod
    def get_header() -> tuple[str, str, str]:
        return ("Test Name", "Attack Successful", "Message")
    
    def to_tuple(self) -> tuple[str, str, str]:
        return (self.name, self.result, self.message)

    def __str__(self):
        return f"{self.name}, {self.result}, {self.message}"

class ROPTest:
    def __init__(self, name, description, binary):
        self.name = name
        self.description = description
        self.binary = binary

    def configure_environment(self, selected_actions: list[ConfigAction]):
        log.info("Configuring environment for test: " + self.name + "\n")
        for action in selected_actions:
            log.info("Taking action: " + action.name)
            action.run()

    def cleanup(self, actions: list[ConfigAction]):
        log.info("Cleaning up environment for test: " + self.name + "\n")
        for action in actions:
            action.cleanup()

    def execute(self) -> float:
        return 0.0

    def run_test(self, actions: list[ConfigAction]) -> TestResult:
        log.info("Test: " + self.name)
        log.info("Description: " + self.description + "\n")

        try:
            self.configure_environment(actions)
            log.info("Running test on binary: " + self.binary + "\n")
            result = self.execute()
        except EOFError as e:
            log.info("EOFError: " + str(e))
            result = 0.0
        finally:
            self.cleanup(actions)

        return TestResult(
            name=self.name,
            result=result,
            message="Test completed successfully"
        )