import logging
import os

def logs():
    log_level = os.getenv("LOGLEVEL", "INFO").upper()
    
    logger = logging.getLogger("aligned_py")
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level, logging.INFO))

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
