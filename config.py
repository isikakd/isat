import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Uygulama genelinde kullanılan temel konfigürasyon sınıfı."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

    # SQLite veritabanı dosyasının yolu
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "isat.db")

    # PDF raporlarının kaydedileceği klasör
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")

    # Port taramasında kontrol edilecek yaygın portlar
    COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]

    # Socket bağlantı timeout süresi (saniye) — tarama takılmasın diye
    SCAN_TIMEOUT = 1.5

    # Kontrol edilecek HTTP güvenlik header'ları
    REQUIRED_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
