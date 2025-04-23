from models import ConfigAction, ROPTest
from config import load_protection_config

from tests import ShellSpawnTest

def main():
    protections = load_protection_config("actions.yaml")

    binary = "./bin/gcc_wxorx"

    test = ShellSpawnTest(binary)

    selected_actions = [protections["disable-aslr"], protections["disable-canary"]]
    result = test.run_test(selected_actions)

    print(result)

if __name__ == "__main__":
    main()