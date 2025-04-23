import subprocess
from pwn import *

class ConfigAction:
    def __init__(self, name, set_cmd, cleanup_cmd):
        self.name = name
        self.set_cmd = set_cmd
        self.cleanup_cmd = cleanup_cmd

    def run(self):
        subprocess.run(self.set_cmd, shell=True, check=True)

    def cleanup(self):
        subprocess.run(self.cleanup_cmd, shell=True, check=True)

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

    def run_test(self, actions: list[ConfigAction]) -> dict:
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

        return {
            "name": self.name,
            "description": self.description,
            "actions": [action.name for action in actions],
            "attack_succeeded": result
        }