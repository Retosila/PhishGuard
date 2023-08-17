import inspect
import re

import requests

from app.errors import InvalidArgumentError, OperationFailedError
from app.logger import Logger
from app.service.phone import *
from app.service.url import *

logger = Logger(__name__)


class InvalidSchemeError(Exception):
    """Http 및 Https가 아닌 Scheme을 가진 URL을 인자로 받았을 때 발생되는 에러"""


class URLNotFoundError(Exception):
    """주어진 URL을 찾을 수 없을 시 발생되는 에러"""


class URLTimeoutError(Exception):
    """주어진 URL에 지정된 타임아웃이 도달하기 전까지 """


class SafeChecker:
    def __init__(self, chrome_driver_path: str):
        self._url_safe_checker = {
            "Node_1": PhishtankURLSafeChecker(),
            "Node_2": WhoXYURLSafeChecker(),
            "Node_3": KISAURLSafeChecker()
        }
        self._phone_safe_checker = {
            "Node_1": OneOneFourPhoneSafeChecker(),
            "Node_2": TheCallPhoneSafeChecker(chrome_driver_path=chrome_driver_path),
            "Node_3": MissedCallPhoneSafeChecker(chrome_driver_path=chrome_driver_path)
        }
        # TODO: Fetch from database
        self._phone_whitelist = ["01092563688"]
        self._phone_blacklist = ["01082539451"]
        self._url_whitelist = ["https://sds.co.kr"]
        self._url_blacklist = ["http://r3born.cc"]

    @staticmethod
    def _is_url(url: str) -> bool:
        regex = re.compile(
            r"^(?:http(s)?://)?"  # optional scheme
            r"(?:(?!((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[?[A-F0-9]*:[A-F0-9:]+\]?))"  # IP address is not allowed
            r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain
            r"localhost)"  # localhost
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)$", re.IGNORECASE)

        is_url = True if re.match(regex, url) is not None else False

        return is_url

    @staticmethod
    def _ensure_scheme(url: str, scheme: str) -> str:
        if not url.startswith(f"{scheme}://"):
            return f"{scheme}://{url}"
        return url

    @staticmethod
    def _get_url_with_scheme(url: str) -> str:
        try:
            https_url = SafeChecker._ensure_scheme(url=url, scheme="https")
            requests.head(https_url, allow_redirects=True, timeout=5)
            return https_url
        except requests.Timeout:
            raise URLTimeoutError
        except requests.RequestException:
            pass

        try:
            http_url = SafeChecker._ensure_scheme(url=url, scheme="http")
            requests.head(http_url, allow_redirects=True, timeout=5)
            return http_url
        except requests.Timeout:
            raise URLTimeoutError
        except requests.RequestException:
            pass

        raise InvalidSchemeError

    @staticmethod
    def _expand_short_url(url: str) -> str:
        try:
            response = requests.head(url=url, allow_redirects=True, timeout=5)
        except requests.Timeout:
            raise URLTimeoutError

        if response.status_code in [404]:
            raise URLNotFoundError
        elif response.status_code in [301, 302]:
            return response.url
        else:
            return url

    @staticmethod
    def _preprocess_url(url: str) -> str:
        url = url.strip()

        is_url = SafeChecker._is_url(url=url)
        if not is_url:
            raise InvalidArgumentError

        url_with_scheme = SafeChecker._get_url_with_scheme(url=url)
        expanded_url = SafeChecker._expand_short_url(url=url_with_scheme)
        return expanded_url

    def check_url_safety(self, url: str) -> tuple[bool, str]:
        logger.debug(f"{self.__class__.__name__}: {inspect.getframeinfo(inspect.currentframe()).function} is called")

        ok: bool
        report: str

        try:
            url = self._preprocess_url(url=url)
        except (URLNotFoundError, URLTimeoutError, InvalidSchemeError):
            # Just allow unacessible url because it's harmless.
            # Our only goal is to filter phishing websites, not to validate.
            ok = True
            report = "URL is not accessible"
            return ok, report
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}")
            raise InvalidArgumentError

        logger.debug(f"{self.__class__.__name__}: Target url={url}")

        try:
            if url in self._phone_whitelist:
                ok = True
                report = "Valid url which listed on whitelist"
                return ok, report

            if url in self._phone_blacklist:
                ok = False
                report = "Invalid url which listed on blacklist"
                return ok, report

            node_1_ok = self._url_safe_checker["Node_1"].is_safe(url=url)
            node_2_ok = self._url_safe_checker["Node_2"].is_safe(url=url)
            node_3_ok = self._url_safe_checker["Node_3"].is_safe(url=url)

            if node_1_ok and node_2_ok and node_3_ok:
                ok = True
            else:
                ok = False

            node_1_report = f"Node_1(PhishtankURLSafeChecker): {'ok' if node_1_ok else 'suspicious'}"
            node_2_report = f"Node_2(WhoXYURLSafeChecker): {'ok' if node_2_ok else 'suspicious'}"
            node_3_report = f"Node_3(KISAURLSafeChecker): {'ok' if node_3_ok else 'suspicious'}"

            logger.debug(f"Report={[node_1_report, node_2_report, node_3_report]}")
            report = "\n".join(f"- {report}" for report in [node_1_report, node_2_report, node_3_report])

            return ok, report
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}")
            raise OperationFailedError

    @staticmethod
    def _normalize_phone_number(phone_number: str) -> str:
        phone_number = phone_number.strip()

        if not all(c.isdigit() or c == "-" or c == " " for c in phone_number):
            raise InvalidArgumentError

        normalized_phone_number = phone_number.replace("-", "").replace(" ", "")
        return normalized_phone_number

    @staticmethod
    def _is_phone_number_safe(checker_and_info: tuple[str, PhoneSafeChecker, str]) -> tuple[bool, str]:
        node_name, checker, phone = checker_and_info
        is_safe = checker.is_safe(phone_number=phone)

        return is_safe, node_name

    def check_phone_safety(self, phone_number: str) -> tuple[bool, str]:
        logger.debug(f"{self.__class__.__name__}: {inspect.getframeinfo(inspect.currentframe()).function} is called")

        ok: bool
        report: str

        try:
            phone_number = self._normalize_phone_number(phone_number=phone_number)
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}")
            raise InvalidArgumentError

        logger.debug(f"{self.__class__.__name__}: Target phone number={phone_number}")

        try:
            if phone_number in self._phone_whitelist:
                ok = True
                report = "Valid phone number which listed on whitelist"
                return ok, report

            if phone_number in self._phone_blacklist:
                ok = False
                report = "Invalid phone number which listed on blacklist"
                return ok, report

            node_1_ok = self._phone_safe_checker["Node_1"].is_safe(phone_number=phone_number)
            node_2_ok = self._phone_safe_checker["Node_2"].is_safe(phone_number=phone_number)
            node_3_ok = self._phone_safe_checker["Node_3"].is_safe(phone_number=phone_number)

            if node_1_ok and node_2_ok and node_3_ok:
                ok = True
            else:
                ok = False

            node_1_report = f"Node_1(OneOneFourPhoneSafeChecker): {'ok' if node_1_ok else 'suspicious'}"
            node_2_report = f"Node_2(TheCallPhoneSafeChecker): {'ok' if node_2_ok else 'suspicious'}"
            node_3_report = f"Node_3(MissedCallPhoneSafeChecker): {'ok' if node_3_ok else 'suspicious'}"

            logger.debug(f"Report={[node_1_report, node_2_report, node_3_report]}")
            report = "\n".join(f"- {report}" for report in [node_1_report, node_2_report, node_3_report])

            return ok, report
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}")
            raise OperationFailedError
