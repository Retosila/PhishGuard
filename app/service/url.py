import inspect
import json
import re
from datetime import datetime

import requests
import tldextract

from app.logger import Logger
from config import CONFIG

__all__ = ["URLSafeChecker", "PhishtankURLSafeChecker", "WhoXYURLSafeChecker", "KISAURLSafeChecker"]

logger = Logger(__name__)


class URLSafeChecker:
    def is_safe(self, url: str) -> bool:
        raise NotImplementedError("This method must be implemented by subclasses")


class PhishtankAPIRequestFailureError(Exception):
    """API 요청이 실패하였을 때 발생하는 에러"""


class PhishtankExtractionFailureError(Exception):
    """값을 추출하다가 오류가 발생하였을 때 발생하는 에러"""


class PhishtankRatelimitExceedError(Exception):
    """API 호출 유량 제한을 초과했을 때 발생하는 에러"""


class PhishtankURLSafeChecker(URLSafeChecker):
    @staticmethod
    def _extract_number_from_string(string: str) -> int:
        numbers = re.findall(r"\d+", string)
        if not numbers:
            raise PhishtankExtractionFailureError

        return int(numbers[0])

    def is_safe(self, url: str) -> bool:
        try:
            logger.debug(
                f"{self.__class__.__name__}: {inspect.getframeinfo(inspect.currentframe()).function} is called")

            api_endpoint = CONFIG["checker"]["url"]["phishtank"]["endpoint"]
            response_format = "json"
            username = CONFIG["checker"]["url"]["phishtank"]["username"]
            user_agent = f"phishtank/{username}"

            headers = {
                "User-Agent": user_agent
            }

            data = {
                "url": url,
                "format": response_format
            }

            logger.debug(f"Send API request. URL={url}")
            res = requests.post(api_endpoint, headers=headers, data=data)

            # Check rate limit
            request_cnt = int(res.headers["X-Request-Count"])
            request_limit = int(res.headers["X-Request-Limit"])
            request_limit_interval = self._extract_number_from_string(string=res.headers["X-Request-Limit-Interval"])

            if request_cnt >= request_limit:
                raise PhishtankRatelimitExceedError

            phishtank_data = json.loads(res.text)

            status: str = phishtank_data["meta"]["status"]
            if not status == "success":
                logger.error(f"Failed to get response from API request")
                raise PhishtankAPIRequestFailureError

            safe: bool

            in_database: bool = phishtank_data["results"]["in_database"]
            if not in_database:
                safe = True
                return safe

            phish = phishtank_data["results"]["valid"]
            safe = True if not phish else False

            return safe
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}: {e}")
            raise


class WhoisURLPreprocessFailureError(Exception):
    """Whois 검색을 위해 URL을 전처리하는데 실패하였을 경우 발생하는 에러"""


class RequestFailureError(Exception):
    """API 요청에 실패하였을 경우 발생하는 에러"""


class ResponseParseFailure(Exception):
    """API 요청에 대한 응답을 파싱하는데 실패하였을 경우 발생하는 에러"""


class WhoXYAPIBalanceDryoutError(Exception):
    """WhoXY API 크레딧 잔액이 고갈되었을 때 발생하는 에러"""


def preprocess_url_for_whois(url: str) -> str:
    try:
        ext = tldextract.extract(url=url)
        preprocessed_url = ext.registered_domain
    except Exception:
        raise WhoisURLPreprocessFailureError

    return preprocessed_url


class WhoXYURLSafeChecker(URLSafeChecker):
    @staticmethod
    def _check_balance() -> bool:
        ok: bool

        api_endpoint = CONFIG["checker"]["url"]["whoxy"]["endpoint"]
        api_key = CONFIG["checker"]["url"]["whoxy"]["api_key"]
        response_format = "json"

        params = {
            "key": api_key,
            "account": "balance",
            "format": response_format
        }

        response = requests.get(url=api_endpoint, params=params)

        try:
            response.raise_for_status()
        except Exception:
            raise RequestFailureError

        whois_data = json.loads(response.text)

        status = whois_data["status"]
        if not status == 1:
            raise RequestFailureError

        credit_balance = whois_data["live_whois_balance"]
        if credit_balance > 0:
            ok = True
        else:
            ok = False

        return ok

    @staticmethod
    def _is_registered_recently(whois_data: dict, within_days: int) -> bool:
        is_newborn: bool

        create_date_str = whois_data["create_date"]
        if not create_date_str:
            raise ResponseParseFailure

        create_date = datetime.strptime(create_date_str, "%Y-%m-%d")
        age = (datetime.utcnow() - create_date).days

        if age <= within_days:
            is_newborn = True
        else:
            is_newborn = False

        return is_newborn

    @staticmethod
    def _has_suspicious_status(whois_data: dict) -> bool:
        is_suspicious: bool

        domain_statuses = whois_data["domain_status"]
        if not domain_statuses:
            raise ResponseParseFailure

        domain_statuses = [domain_status.lower() for domain_status in domain_statuses]
        suspicious_statuses = ["clienthold", "inactive"]

        for domain_status in domain_statuses:
            if domain_status in suspicious_statuses:
                is_suspicious = True
                return is_suspicious

        is_suspicious = False
        return is_suspicious

    @staticmethod
    def _has_anonymized_registrant(whois_data: dict) -> bool:
        is_anonymous: bool

        registrant_contact = whois_data["registrant_contact"]
        if not registrant_contact:
            raise ResponseParseFailure

        company_name: str = registrant_contact["company_name"].lower()

        if company_name.startswith("redacted"):
            is_anonymous = True
        else:
            is_anonymous = False

        return is_anonymous

    def is_safe(self, url: str) -> bool:
        try:
            safe: bool

            logger.debug(
                f"{self.__class__.__name__}: {inspect.getframeinfo(inspect.currentframe()).function} is called")

            has_credit = self._check_balance()
            if not has_credit:
                raise WhoXYAPIBalanceDryoutError("WhoXY API credit balance is all dried out")

            api_endpoint = CONFIG["checker"]["url"]["whoxy"]["endpoint"]
            api_key = CONFIG["checker"]["url"]["whoxy"]["api_key"]
            response_format = "json"
            preprocessed_url = preprocess_url_for_whois(url=url)

            params = {
                "key": api_key,
                "whois": preprocessed_url,
                "format": response_format
            }

            logger.debug(f"Send API request. URL={preprocessed_url}")
            response = requests.get(url=api_endpoint, params=params)

            try:
                response.raise_for_status()
            except Exception:
                raise RequestFailureError

            whois_data = json.loads(response.text)

            status = whois_data["status"]
            if not status == 1:
                status_reason: str = whois_data["status_reason"].lower()
                if status_reason.startswith("unsupported domain extension"):
                    # WhoXY support domain is blackbox. So just pass unsupported domain
                    safe = True
                    return safe
                raise RequestFailureError

            newborn: bool = self._is_registered_recently(whois_data=whois_data, within_days=30)
            suspicious: bool = self._has_suspicious_status(whois_data=whois_data)
            anonymous: bool = self._has_anonymized_registrant(whois_data=whois_data)

            logger.debug(f"Result=newborn: {newborn}, suspicious: {suspicious}, anonymous: {anonymous}")

            if newborn or suspicious or anonymous:
                safe = False
            else:
                safe = True

            return safe
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}: {e}")
            raise


class KISAURLSafeChecker(URLSafeChecker):
    @staticmethod
    def _is_registered_recently(whois_data: dict, within_days: int) -> bool:
        is_newborn: bool

        registered_date_str = whois_data["regDate"]
        if not registered_date_str:
            raise ResponseParseFailure

        registered_date = datetime.strptime(registered_date_str, "%Y. %m. %d.")
        age = (datetime.utcnow() - registered_date).days

        if age <= within_days:
            is_newborn = True
        else:
            is_newborn = False

        return is_newborn

    @staticmethod
    def _has_suspicious_status(whois_data: dict) -> bool:
        is_suspicious: bool

        domain_statuses = whois_data["domainStatus"]
        if not domain_statuses:
            is_suspicious = False
            return is_suspicious

        domain_statuses = [domain_status.lower() for domain_status in domain_statuses]
        suspicious_statuses = ["clienthold", "inactive"]

        for domain_status in domain_statuses:
            if domain_status in suspicious_statuses:
                is_suspicious = True
                return is_suspicious

        is_suspicious = False
        return is_suspicious

    @staticmethod
    def _has_anonymized_registrant(whois_data: dict) -> bool:
        is_anonymous: bool

        registrant_name: str = whois_data["regName"].lower()

        if registrant_name.startswith("redacted"):
            is_anonymous = True
        else:
            is_anonymous = False

        return is_anonymous

    def is_safe(self, url: str) -> bool:
        try:
            safe: bool

            logger.debug(
                f"{self.__class__.__name__}: {inspect.getframeinfo(inspect.currentframe()).function} is called")

            api_endpoint = CONFIG["checker"]["url"]["kisa"]["endpoint"]
            service_key = CONFIG["checker"]["url"]["kisa"]["service_key"]
            response_format = "json"
            preprocessed_url = preprocess_url_for_whois(url=url)

            params = {
                "serviceKey": service_key,
                "query": preprocessed_url,
                "answer": response_format
            }

            logger.debug(f"Send API request. URL={preprocessed_url}")
            response = requests.get(url=api_endpoint, params=params)

            try:
                response.raise_for_status()
            except Exception:
                raise RequestFailureError

            response_body = json.loads(response.text)["response"]

            result_code = response_body["result"]["result_code"]
            if not result_code == "10000":
                if result_code == "031":
                    # Do not handle url which is not supported by KISA.
                    safe = True
                    return safe

                raise RequestFailureError

            whois_data = response_body["whois"]["krdomain"]

            newborn: bool = self._is_registered_recently(whois_data=whois_data, within_days=30)
            suspicious: bool = self._has_suspicious_status(whois_data=whois_data)
            anonymous: bool = self._has_anonymized_registrant(whois_data=whois_data)

            logger.debug(f"Result=newborn: {newborn}, suspicious: {suspicious}, anonymous: {anonymous}")

            if newborn or suspicious or anonymous:
                safe = False
            else:
                safe = True

            return safe
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}: {e}")
            raise
