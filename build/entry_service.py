import multiprocessing
from schoolshield.service import service_main
if __name__ == "__main__":
    multiprocessing.freeze_support()
    service_main()
