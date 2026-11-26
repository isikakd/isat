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

    # SQLite veritabanını (yoksa) oluştur
    from app.models.database import init_db
    init_db(app)

    # Blueprint'leri (route modüllerini) kaydet
    from app.routes.main_routes import main_bp
    app.register_blueprint(main_bp)

    # Genel hata sayfaları: kullanıcıya Flask'ın varsayılan çirkin hata
    # sayfası yerine, uygulamanın kendi temasıyla tutarlı bir sayfa gösterir.
    from flask import render_template

    @app.errorhandler(404)
    def not_found(e):
        return render_template(
            "error.html", code=404, title="Page Not Found",
            message="The page you're looking for doesn't exist."
        ), 404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template(
            "error.html", code=500, title="Internal Server Error",
            message="Something went wrong on our end. Please try again."
        ), 500

    return app