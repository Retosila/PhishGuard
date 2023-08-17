import os
from typing import Any

import toml

__all__ = ["CONFIG"]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE_PATH = os.path.join(BASE_DIR, "config.toml")


class ConfigLoader:
    def __init__(self, config_path: str):
        self._config_path: str = config_path
        self._config = None

    def load(self):
        with open(file=self._config_path, mode="r") as f:
            self._config = toml.load(f)

    def get_config(self) -> dict[str, Any]:
        return self._config


_config_loader = ConfigLoader(config_path=CONFIG_FILE_PATH)
_config_loader.load()
CONFIG = _config_loader.get_config()
