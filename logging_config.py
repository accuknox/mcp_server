# logging_config.py
import logging

# Define a named global logger
LOGGER_NAME = "mcp_server"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)  # or DEBUG, as needed

# Configure console handler
console = logging.StreamHandler()
console.setLevel(logging.INFO)

# Simplified formatter
formatter = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(funcName)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
console.setFormatter(formatter)

# Optional: file logging
# file_handler = logging.FileHandler("app.log")
# file_handler.setLevel(logging.DEBUG)
# file_handler.setFormatter(formatter)
# logger.addHandler(file_handler)

logger.addHandler(console)
