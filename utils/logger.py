# this module sets up the logging system used by the application.
# it creates two separate loggers:
# - one for security-related events
# - one for normal access/activity events
#
# these logs help track what the system is doing and make it easier
# to investigate suspicious behavior or verify that security controls worked.

import logging
from config import SECURITY_LOG_FILE, ACCESS_LOG_FILE


def _build_logger(name: str, filepath):
    # create and configure a logger object.
    #
    # parameters:
    # - name: the internal name of the logger
    # - filepath: the file where log messages should be written
    #
    # this helper avoids repeating the same setup code for both loggers.

    # get or create a logger with the given name.
    logger = logging.getLogger(name)

    # set the minimum logging level for this logger.
    # info means the logger will record info, warning, error, and critical messages.
    logger.setLevel(logging.INFO)

    # only add a file handler if the logger does not already have one.
    # this prevents duplicate handlers from being attached if the module
    # is imported more than once.
    if not logger.handlers:
        # create a handler that writes log messages to the given file.
        handler = logging.FileHandler(filepath)

        # define the format of each log line.
        # this includes:
        # - timestamp
        # - severity level
        # - the actual message
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )

        # attach the formatter to the handler.
        handler.setFormatter(formatter)

        # connect the handler to the logger.
        logger.addHandler(handler)

    return logger


# create the logger used for security-related events such as:
# - failed logins
# - denied actions
# - rate-limit triggers
# - account lockouts
security_logger = _build_logger("security_logger", SECURITY_LOG_FILE)

# create the logger used for normal access/activity events such as:
# - successful uploads
# - successful downloads
# - dashboard access
# - successful shares
access_logger = _build_logger("access_logger", ACCESS_LOG_FILE)


def log_security_event(message: str, severity: str = "INFO"):
    # write a message to the security log using the requested severity level.
    #
    # parameters:
    # - message: the text to record in the security log
    # - severity: the importance level of the event
    #
    # supported severity values:
    # - critical
    # - error
    # - warning
    # - info
    #
    # if an unknown value is provided, the function defaults to info.

    # convert the severity string to uppercase so that
    # values like "warning" and "WARNING" are treated the same way.
    severity = severity.upper()

    # route the message to the matching logging method.
    if severity == "CRITICAL":
        security_logger.critical(message)
    elif severity == "ERROR":
        security_logger.error(message)
    elif severity == "WARNING":
        security_logger.warning(message)
    else:
        # default to info for normal or unrecognized severity values.
        security_logger.info(message)


def log_access_event(message: str):
    # write a message to the access log.
    #
    # access logs are used for normal successful actions and general activity,
    # so they are always recorded at the info level.
    access_logger.info(message)