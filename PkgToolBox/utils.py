class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_aligned(name: str, text: str, color: str = ''):
    print(f"{name:>20}  {color}{bcolors.BOLD}{text}{bcolors.ENDC}")


class Logger:
    @staticmethod
    def log_information(message):
        print(f"INFO: {message}")

    @staticmethod
    def log_warning(message):
        print(f"WARNING: {message}")

    @staticmethod
    def log_error(message):
        print(f"ERROR: {message}")
