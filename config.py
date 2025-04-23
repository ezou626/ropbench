from models import ConfigAction
import yaml

def load_protection_config(path) -> dict[str, ConfigAction]:
    with open(path) as f:
        data = yaml.safe_load(f)

    actions = {}
    for prot in data.get("actions", []):
        action = ConfigAction(
            name=prot["name"],
            set_cmd=prot["set"],
            cleanup_cmd=prot["cleanup"]
        )
        actions[prot["name"]] = action
    return actions