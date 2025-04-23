import yaml
import subprocess

class ConfigAction:
    def __init__(self, name, set_cmd, cleanup_cmd):
        self.name = name
        self.set_cmd = set_cmd
        self.cleanup_cmd = cleanup_cmd

    def run(self):
        print(f"Running command for {self.name}: {self.set_cmd}")
        subprocess.run(self.set_cmd, shell=True, check=True)

    def cleanup(self):
        print(f"Running cleanup for {self.name}: {self.cleanup_cmd}")
        subprocess.run(self.cleanup_cmd, shell=True, check=True)

class ROPTest:
    def __init__(self, name, description, binary):
        self.name = name
        self.description = description
        self.binary = binary

    def configure_environment(self, selected_actions: list[ConfigAction]):
        print("Configuring environment for test: " + self.name + "\n")
        for action in selected_actions:
            print("Taking action: " + action.name)
            action.run()

    def cleanup(self, actions: list[ConfigAction]):
        print("Cleaning up environment for test: " + self.name + "\n")
        for action in actions:
            action.cleanup()

    def preamble(self):
        pass

    def execute(self) -> bool:
        pass

    def run_test(self, actions: list[ConfigAction]) -> dict:
        print("Test: " + self.name)
        print("Description: " + self.description + "\n")

        try:
            self.configure_environment(actions)
            print("Running test on binary: " + self.binary + "\n")
            result = self.execute()
        except Exception as e:
            print(f"An error occurred during test execution: {e}")
            result = False
        finally:
            self.cleanup(actions)

        print("Result: " + ("Failed" if result else "Passed") + "\n")

        return {
            "name": self.name,
            "description": self.description,
            "actions": [action.name for action in actions],
            "attack_succeeded": result
        }