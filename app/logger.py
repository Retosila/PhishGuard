import logging
import os
import sys

import colorlog

from config import CONFIG

__all__ = ["Logger", "init_logger"]

AVAILABLE_HANDLERS = ["file", "stream"]  # 로그 핸들러는 file, stream 두 가지 타입만 지원한다.


class NullHandler(logging.Handler):
    def emit(self, record):
        pass


def suppress_logging_for(logger_name: str):
    logger = logging.getLogger(logger_name)
    logger.addHandler(NullHandler())
    logger.propagate = False


def init_logger():
    logger = logging.getLogger()
    logger.propagate = False

    log_level: str = logging.getLevelName(CONFIG["logger"]["level"].upper())
    logger.setLevel(log_level)

    formatter = colorlog.ColoredFormatter(
        fmt="%(log_color)s %(asctime)s [%(levelname)s] %(message)s (%(name)s:%(funcName)s:%(lineno)d)",
        datefmt='%Y-%m-%d %H:%M:%S')

    handlers: list[str] = [handler.lower().strip() for handler in CONFIG["logger"]["handler"]]

    if not handlers:
        sys.stderr.write(
            "No logging handler is set. Recommend to set any handlers for logger. Available handlers are 'file' and "
            "'stream'")
        return None

    for handler in handlers:
        if handler not in AVAILABLE_HANDLERS:
            sys.stderr.write(
                f"Invalid handler is detected: {handler}. Available handlers are 'file' and 'stream'")
            sys.exit(1)

    if "file" in handlers:
        if not os.path.isdir(CONFIG["logger"]["filepath"]):
            os.mkdir(CONFIG["logger"]["filepath"])
        file_handler = logging.FileHandler(f"{CONFIG['logger']['filepath']}app.log")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if "stream" in handlers:
        stream_handler = colorlog.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    # Ignore logs for following module
    suppress_logging_for(logger_name="selenium")  # Selenium
    suppress_logging_for(logger_name="urllib3")  # urllib
    suppress_logging_for(logger_name="tldextract")  # tldextract
    suppress_logging_for(logger_name="filelock")  # filelock

    logger.info("Logger is initialized")
    logger.info(f"Log level is set to {CONFIG['logger']['level']}")


class Logger:
    def __init__(self, name):
        self._logger = logging.getLogger(name)

    def debug(self, message):
        self._logger.debug(message)

    def info(self, message):
        self._logger.info(message)

    def warning(self, message):
        self._logger.warning(message)

    def error(self, message):
        self._logger.error(message)

    def critical(self, message):
        self._logger.critical(message)
