import re

class IllegalNameCheck:
    @staticmethod
    def is_valid_file_name(expression, platform_independent):
        s_pattern = r"^(?!^(PRN|AUX|CLOCK\$|NUL|CON|COM\d|LPT\d|\..*)(\..+)?$)[^\x00-\x1f\\?*:\";|/]+$"
        if platform_independent:
            s_pattern = r"^(([a-zA-Z]:|\\)\\)?(((\.)|(\.\.)|([^\\/:\*\?\"<>\. ](([^\\/:\*\?\"<>\. ])|([^\\/:\*\?\"<>]*[^\\/:\*\?\"<>\. ]))?))\\)*[^\\/:\*\?\"<>\. ](([^\\/:\*\?\"<>\. ])|([^\\/:\*\?\"<>]*[^\\/:\*\?\"<>\. ]))?$"
        return re.match(s_pattern, expression) is not None