from enum import IntEnum

from flask import Flask, Blueprint, jsonify, request
from flask_cors import CORS

from app.errors import OperationFailedError, InvalidArgumentError
from app.logger import Logger
from app.service import SafeChecker
from app.utils import CHROME_DRIVER_PATH
from config import CONFIG

__all__ = ["init_api_server"]

logger = Logger(__name__)


class StatusCode(IntEnum):
    OK = 200
    BAD_REQUEST = 400
    INTERNAL_SERVER_ERROR = 500


class APIServer:
    def __init__(self):
        self._server = Flask(__name__)
        self._checker = SafeChecker(chrome_driver_path=CHROME_DRIVER_PATH)

    def register_blueprints(self):
        checker = Blueprint(name=CONFIG["server"]["name"],
                            import_name=__name__,
                            url_prefix=CONFIG["server"]["url_prefix"])

        @checker.route(rule="/check/phone", methods=["POST"])
        def check_phone_safety():
            data = request.json
            phone_number = data.get("phone_number")

            try:
                ok, report = self._checker.check_phone_safety(phone_number=phone_number)
                return jsonify({
                    "status": StatusCode.OK,
                    "is_safe": ok,
                    "report": report
                })
            except InvalidArgumentError:
                return jsonify({
                    "status": StatusCode.BAD_REQUEST
                })
            except OperationFailedError:
                return jsonify({
                    "status": StatusCode.INTERNAL_SERVER_ERROR
                })

        @checker.route(rule="/check/url", methods=["POST"])
        def check_url_safety():
            data = request.json
            url = data.get("url")

            try:
                ok, report = self._checker.check_url_safety(url=url)
                return jsonify({
                    "status": StatusCode.OK,
                    "is_safe": ok,
                    "report": report
                })
            except InvalidArgumentError:
                return jsonify({
                    "status": StatusCode.BAD_REQUEST
                })
            except OperationFailedError:
                return jsonify({
                    "status": StatusCode.INTERNAL_SERVER_ERROR
                })

        self._server.register_blueprint(blueprint=checker)

    def enable_cors(self):
        CORS(app=self._server, origins=CONFIG["server"]["allowed_origins"])

    def run(self):
        self._server.run(host=CONFIG["server"]["host"],
                         port=CONFIG["server"]["port"],
                         debug=CONFIG["server"]["use_debug_mode"],
                         use_reloader=CONFIG["server"]["user_reloader"])


def init_api_server():
    api_server = APIServer()
    api_server.register_blueprints()
    api_server.enable_cors()
    api_server.run()
