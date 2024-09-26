class Extension:
    @staticmethod
    def get_until_or_empty(text, stop_at="-"):
        if text:
            char_location = text.find(stop_at)
            if char_location > 0:
                return text[:char_location]
        return ""