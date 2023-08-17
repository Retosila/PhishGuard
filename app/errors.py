__all__ = ["InvalidArgumentError", "OperationFailedError"]


class InvalidArgumentError(Exception):
    """유효하지 않은 인자를 입력받았을 때 발생되는 에러"""


class OperationFailedError(Exception):
    """예상치 못하게 함수 및 메소드의 동작이 실패했을 때 발생되는 에러"""
