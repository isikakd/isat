import os
from flask import Flask
from config import config_map


def create_app(config_name="default"):
    """
    Flask application factory.

    Bu fonksiyon, konfigürasyona göre bir Flask uygulaması oluşturur.
    App factory pattern kullanmamızın sebebi:
    - Testlerde farklı config ile app oluşturabilmek
    - Blueprint'leri (route gruplarını) düzenli şekilde kaydedebilmek
    """
    app = Flask(__name__)
    app.config.from_object(config_map.get(config_name, config_map["default"]))

    # Gerekli klasörlerin var olduğundan emin ol
    os.makedirs(os.path.dirname(app.config["DATABASE_PATH"]), exist_ok=True)
    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

    # Blueprint'leri (route modüllerini) kaydet
    from app.routes.main_routes import main_bp
    app.register_blueprint(main_bp)

    return app
