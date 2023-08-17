import inspect
import re
import time

import requests
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait
from selenium_stealth import stealth

from app.logger import Logger

__all__ = ["PhoneSafeChecker", "OneOneFourPhoneSafeChecker", "MissedCallPhoneSafeChecker", "TheCallPhoneSafeChecker"]

logger = Logger(__name__)


class PhoneSafeChecker:
    def is_safe(self, phone_number: str) -> bool:
        raise NotImplementedError("This method must be implemented by subclasses")


class OneOneFourPhoneSafeChecker(PhoneSafeChecker):
    def is_safe(self, phone_number: str) -> bool:
        try:
            logger.debug(
                f"{self.__class__.__name__}: {inspect.getframeinfo(inspect.currentframe()).function} is called")

            headers = {
                "Accept-Language": "en-US,en;q=0.9",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/114.0.0.0 Whale/3.21.192.22 Safari/537.36",
                "Content-Type": "application/json"
            }
            url = "https://www.114.co.kr/action/search/scam"
            payload = {"spam_kwd_tp_cd": "P", "spam_keyword": phone_number}

            response = requests.post(url, headers=headers, json=payload)
            if response.status_code != 200:
                raise Exception(f"HTTP request failed with status {response.status_code}")

            data = response.json()["data"]

            if data["whowho"] is not None or data["kisa"] is not None or data["thecheat"] is not None:
                return False

            return True
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}")
            raise


class TheCallPhoneSafeChecker(PhoneSafeChecker):
    _MAX_RETRIES = 3

    def __init__(self, chrome_driver_path: str):
        self._chrome_driver_path = chrome_driver_path

    def is_safe(self, phone_number: str) -> bool:
        try:
            logger.debug(
                f"{self.__class__.__name__}: {inspect.getframeinfo(inspect.currentframe()).function} is called")

            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                         "Chrome/91.0.4472.124 Safari/537.36"

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument(f"user-agent={user_agent}")
            chrome_options.add_argument("--remote-debugging-port=0")
            chrome_options.add_argument("--log-level=3")
            chrome_options.add_experimental_option("detach", True)
            chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])

            service = Service(executable_path=self._chrome_driver_path)
            driver = webdriver.Chrome(service=service, options=chrome_options)
            stealth(driver,
                    languages=["en-US", "en"],
                    vendor="Google Inc.",
                    platform="Win32",
                    webgl_vendor="Intel Inc.",
                    renderer="Intel Iris OpenGL Engine",
                    fix_hairline=True,
                    )

            driver.get(url="https://www.thecall.co.kr/")
            tel_input = WebDriverWait(driver=driver, timeout=10).until(
                ec.presence_of_element_located(
                    (By.CSS_SELECTOR, "#sidebar > section.number_search > form > input.stx")))

            tel_input.send_keys(phone_number)
            query_button = driver.find_element(By.CSS_SELECTOR,
                                               "#sidebar > section.number_search > form > input.primary-button")
            query_button.click()

            is_safe: bool
            try:
                WebDriverWait(driver=driver, timeout=10).until(
                    ec.presence_of_element_located((By.CSS_SELECTOR,
                                                    "#content-below-adsense-top > div.board-view > article > "
                                                    "section > div.article-vote > a:nth-child(1) > span")))
                is_safe = False
            except TimeoutException:
                is_safe = True

            driver.quit()

            return is_safe
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}")
            raise


class ExtractLevelFailureError(Exception):
    """레벨 추출이 실패했을 때 발생하는 에러"""


class MissedCallPhoneSafeChecker(PhoneSafeChecker):
    _MAX_RETRIES = 3

    def __init__(self, chrome_driver_path: str):
        self._chrome_driver_path = chrome_driver_path

    @staticmethod
    def _extract_level(text: str) -> int:
        match = re.search(r"\(Lv\.(\d+)\)", text)
        if match:
            return int(match.group(1))
        else:
            raise ExtractLevelFailureError("Failed to extract level")

    @staticmethod
    def _find_sup(element: WebElement):
        try:
            return element.find_element(By.TAG_NAME, "sup")
        except NoSuchElementException:
            for child in element.find_elements(By.XPATH, "./*"):
                sup_element = MissedCallPhoneSafeChecker._find_sup(element=child)
                if sup_element:
                    return sup_element
        return None

    def is_safe(self, phone_number: str) -> bool:
        try:
            logger.debug(
                f"{self.__class__.__name__}: {inspect.getframeinfo(inspect.currentframe()).function} is called")

            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                         "Chrome/91.0.4472.124 Safari/537.36"

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument(f"user-agent={user_agent}")
            chrome_options.add_argument("--remote-debugging-port=0")
            chrome_options.add_argument("--log-level=3")
            chrome_options.add_experimental_option("detach", True)
            chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])

            service = Service(executable_path=self._chrome_driver_path)
            driver = webdriver.Chrome(service=service, options=chrome_options)
            stealth(driver,
                    languages=["en-US", "en"],
                    vendor="Google Inc.",
                    platform="Win32",
                    webgl_vendor="Intel Inc.",
                    renderer="Intel Iris OpenGL Engine",
                    fix_hairline=True,
                    )

            driver.get(url="http://www.missed-call.com/")

            tel_input = WebDriverWait(driver=driver, timeout=10).until(
                ec.presence_of_element_located((By.ID, "pnum")))
            tel_input.send_keys(phone_number)
            query_button = driver.find_element(By.ID, "submitButton")
            query_button.click()

            retry_count = 0
            is_safe: bool = False

            while retry_count < self._MAX_RETRIES:
                try:
                    result_is_spam = WebDriverWait(driver=driver, timeout=10).until(
                        ec.presence_of_element_located((By.ID, "result_is_spam")))
                    sup_element = self._find_sup(element=result_is_spam)

                    if not sup_element:
                        raise ExtractLevelFailureError

                    spam_level_text = sup_element.text
                    spam_level = self._extract_level(text=spam_level_text)
                    if spam_level > 0:
                        is_safe = False
                    else:
                        is_safe = True
                    break
                except ExtractLevelFailureError:
                    if retry_count < self._MAX_RETRIES:
                        logger.debug(f"Failed to extract level. Current retry count={retry_count}")
                        time.sleep(3)
                        retry_count += 1
                    else:
                        logger.debug(f"Failed to extract level. All retries are failed")
                        raise
                except Exception as e:
                    logger.debug(f"{self.__class__.__name__}: "
                                 f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}")
                    raise

            driver.quit()

            return is_safe
        except Exception as e:
            logger.debug(f"{self.__class__.__name__}: "
                         f"{inspect.getframeinfo(inspect.currentframe()).function}: {type(e).__name__}")
            raise
