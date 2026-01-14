import re

URL_REGEX = re.compile(r'https?://[^\s<>"\']+')

def dedupe(items):
    seen = set()
    out = []
    for x in items:
        x = x.strip().rstrip(").,;!\"'<>")
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out
