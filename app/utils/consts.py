from webdriver_manager.chrome import ChromeDriverManager

__all__ = ["CHROME_DRIVER_PATH"]

CHROME_DRIVER_PATH = ChromeDriverManager().install()
