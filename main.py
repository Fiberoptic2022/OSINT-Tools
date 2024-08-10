# main.py
from virustotal_checker import VirusTotalChecker
from virus_total_gui import VirusTotalApp

if __name__ == "__main__":
    virustotal_checker = VirusTotalChecker()
    app = VirusTotalApp(virustotal_checker)
    app.mainloop()
