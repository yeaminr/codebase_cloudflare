import logging


class ExcludeFilter(logging.Filter):
    """
    Custom logging filter to exclude specific log messages.
    """

    def __init__(self, exclude_messages = None):
        super().__init__()
        if exclude_messages is None:
            exclude_messages = []
        self.exclude_messages = exclude_messages

    def filter(self, record):
        return not any(msg in record.getMessage() for msg in self.exclude_messages)
