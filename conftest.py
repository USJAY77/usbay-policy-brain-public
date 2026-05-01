import warnings

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL.*")
warnings.filterwarnings("ignore", message=".*LibreSSL.*")
