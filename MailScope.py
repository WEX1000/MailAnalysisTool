import sys

from app.analyzer import mail_analysis

LOGO = """ __   __  _______  ___   ___      _______  _______  _______  _______  _______ 
|  |_|  ||   _   ||   | |   |    |       ||       ||       ||       ||       |
|       ||  |_|  ||   | |   |    |  _____||       ||   _   ||    _  ||    ___|
|       ||       ||   | |   |    | |_____ |       ||  | |  ||   |_| ||   |___ 
|       ||       ||   | |   |___ |_____  ||      _||  |_|  ||    ___||    ___|
| ||_|| ||   _   ||   | |       | _____| ||     |_ |       ||   |    |   |___ 
|_|   |_||__| |__||___| |_______||_______||_______||_______||___|    |_______|
------------------------------------------------------------------------------"""

def main():
    vt_on = False
    abuse_on = False
    urlscan_on = False
    args = sys.argv[1:]

    if not args:
        print(LOGO)
        print("Missing argument, use -h")
        return

    file_path = None
    i = 0
    while i < len(args):
        if args[i] == "-h":
            print(LOGO)
            print("  -h            show help")
            print("  -f <file>     path to .eml file")
            print("  -vt           enable VirusTotal")
            print("  -url          enable urlscan.io")
            print("  -abuse        enable AbuseIPDB")
            print("-" * 78)
            return
        elif args[i] == "-f" and i + 1 < len(args):
            file_path = args[i + 1]
            i += 2
            continue
        elif args[i] == "-vt":
            vt_on = True; i += 1; continue
        elif args[i] == "-url":
            urlscan_on = True; i += 1; continue
        elif args[i] == "-abuse":
            abuse_on = True; i += 1; continue
        else:
            print(LOGO)
            print("Invalid argument, use -h")
            return

    if not file_path or not file_path.lower().endswith(".eml"):
        print(LOGO)
        print("Missing/invalid file path, use -h")
        return

    print(LOGO)
    print("File:", file_path)
    print("-" * 78)
    mail_analysis(file_path, vt_on=vt_on, abuse_on=abuse_on, urlscan_on=urlscan_on)

if __name__ == "__main__":
    main()
