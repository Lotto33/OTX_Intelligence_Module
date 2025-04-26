import logging
from datetime import datetime

logger = logging.getLogger('log')
logger.setLevel(logging.DEBUG)  

# Create handlers for console and file
current_date = datetime.now().strftime('%Y-%m-%d')
console_passer = logging.StreamHandler()
file_maker = logging.FileHandler(f'OTX_Scan_Info ({current_date}).log')

# Set the level of logging for handlers
console_passer.setLevel(logging.DEBUG)
file_maker.setLevel(logging.DEBUG)

# Create a formatter for the logs
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console_passer.setFormatter(formatter)
file_maker.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(console_passer)
logger.addHandler(file_maker)

# Example log messages to test if logging works
logger.debug("Logger initialized. Testing log at DEBUG level.")