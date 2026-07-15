from flask import Blueprint, render_template, request, jsonify
from app.services.port_scanner import scan_common_ports
from app.services.header_analyzer import analyze_headers
from app.utils.validators import validate_target

# Bu blueprint, dashboard ve tarama ile ilgili tüm route'ları gruplar
main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def dashboard():
    """Ana dashboard sayfasını render eder."""
    return render_template("index.html", active_page="dashboard")


@main_bp.route("/scan", methods=["POST"])
def scan():
    """
    Gerçek tarama endpoint'i.
    Frontend'den (JavaScript/fetch) JSON gövdesinde {"target": "..."}
    şeklinde bir istek alır, port tarama servisini çalıştırır ve
    sonucu JSON olarak döner.

    İlerleyen adımlarda bu fonksiyona HTTP header analizi, SSL analizi,
    DNS/WHOIS sorgulama ve risk skorlama da eklenecek.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    # Giriş doğrulama: boş veya hatalı formatlı hedefleri en başta ele alıyoruz
    is_valid, error_message = validate_target(target)
    if not is_valid:
        return jsonify({"error": error_message}), 400

    try:
        port_results = scan_common_ports(target)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        # Beklenmeyen bir hata durumunda uygulamanın çökmesini engelliyoruz
        return jsonify({"error": "Tarama sırasında beklenmeyen bir hata oluştu."}), 500

    # HTTP güvenlik başlıklarını analiz et.
    # Bu adım port taramasından bağımsızdır; port taraması hata vermeden
    # tamamlansa bile header analizi ayrı bir işlemdir, o yüzden ayrı
    # bir try/except bloğunda ele alıyoruz.
    try:
        header_results = analyze_headers(target)
    except Exception:
        header_results = {
            "reachable": False,
            "url": None,
            "present": [],
            "missing": [],
            "error": "Header analizi sırasında beklenmeyen bir hata oluştu."
        }

    return jsonify({
        "target": target,
        "ports": port_results,
        "headers": header_results
    })