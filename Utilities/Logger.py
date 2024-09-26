import os
from datetime import datetime

class Logger:
    log_filename = "PS4PKGToolLog.txt"
    lock_object = None

    @staticmethod
    def flush_log():
        with open(Logger.log_filename, 'w'):
            pass

    @staticmethod
    def log_information(msg):
        Logger.log("INFO", msg)

    @staticmethod
    def log_warning(msg):
        Logger.log("WARN", msg)

    @staticmethod
    def log_error(msg, ex=None):
        Logger.log("ERR", msg, ex)

    @staticmethod
    def log(level, msg, ex=None):
        try:
            if msg:
                with open(Logger.log_filename, 'a') as f:
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_message = f"{now} : [{level}] {msg}"
                    if ex:
                        log_message += f"\n{ex}"
                    f.write(log_message + "\n")
        except Exception as e:
            print(f"Logging error: {e}")

    @staticmethod
    def read_logs():
        try:
            with open(Logger.log_filename, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error reading log file: {str(e)}"