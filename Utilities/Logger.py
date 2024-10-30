import logging
import sys

class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(filename='PS4PKGToolLog.txt', level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s: %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

    @staticmethod
    def log_information(message):
        try:
            logging.info(message)
        except Exception as e:
            logging.error(f"Error in logging: {str(e)}")

    @staticmethod
    def log_error(message):
        try:
            logging.error(message)
        except Exception as e:
            logging.error(f"Error in logging: {str(e)}")

    @staticmethod
    def log_warning(message):
        try:
            logging.warning(message)
        except Exception as e:
            logging.error(f"Error in logging: {str(e)}")