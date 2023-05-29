import logging


class CustomFormatter(logging.Formatter):
    """Logging colored formatter, adapted from https://stackoverflow.com/a/56944256/3638629"""

    grey = "\x1b[38;21m"
    blue = "\x1b[38;5;39m"
    yellow = "\x1b[38;5;226m"
    red = "\x1b[38;5;196m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt.split("|")
        self.FORMATS = {
            logging.DEBUG: self.grey
            + self.fmt[0]
            + self.fmt[1]
            + self.reset
            + self.fmt[2],
            logging.INFO: self.blue
            + self.fmt[0]
            + self.fmt[1]
            + self.reset
            + self.fmt[2],
            logging.WARNING: self.yellow
            + self.fmt[0]
            + self.fmt[1]
            + self.reset
            + self.fmt[2],
            logging.ERROR: self.red
            + self.fmt[0]
            + self.fmt[1]
            + self.reset
            + self.fmt[2],
            logging.CRITICAL: self.bold_red
            + self.fmt[0]
            + self.fmt[1]
            + self.reset
            + self.fmt[2],
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


# Create custom logger logging all five levels
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Define format for logs
fmt = "%(asctime)s | %(levelname)8s | %(message)s"

# Create stdout handler for logging to the console (logs all five levels)
stdout_handler = logging.StreamHandler()
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(CustomFormatter(fmt))
logger.addHandler(stdout_handler)
