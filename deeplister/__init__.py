"""DeepLister: Recursive folder, file, and nested archive inventory tool."""

import logging

__version__ = "1.2.0"
APP_NAME = "DeepLister"
APP_ID = "yunhyok.DeepLister"

# Library-style default: stay silent until logsetup.start_file_logging() attaches a file handler
logging.getLogger("deeplister").addHandler(logging.NullHandler())
