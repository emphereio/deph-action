"""Tiny app whose only job is to make a vulnerable dependency reachable, so the
deph-action e2e suite has a deterministic in-path CVE to find."""
import yaml


def load_config(text: str):
    # Reachable use of the vulnerable yaml.load (CVE-2020-14343 in pyyaml < 5.4).
    return yaml.load(text, Loader=yaml.FullLoader)


if __name__ == "__main__":
    print(load_config("name: deph"))
