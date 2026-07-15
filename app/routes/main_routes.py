from flask import Blueprint, render_template, request, jsonify
from app.services.port_scanner import scan_common_ports

# Bu blueprint, dashboard ve tarama ile ilgili tüm route'ları gruplar
main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def dashboard():
    """Ana dashboard sayfasını render eder."""
    return render_template("index.html", active_page="dashboard")


@main_bp.route("/test/port-scan")
def test_port_scan():
    """
    GEÇİCİ TEST ROUTE'U.
    Port scanner servisinin doğru çalışıp çalışmadığını tarayıcıdan
    kontrol edebilmek için eklendi. Adım sonunda dashboard'a
    tam entegre edilince bu route kaldırılacak / güncellenecek.

    Kullanım: http://127.0.0.1:5000/test/port-scan?target=example.com
    """
    target = request.args.get("target")

    if not target:
        return jsonify({"error": "target parametresi gerekli. Örn: ?target=example.com"}), 400

    try:
        results = scan_common_ports(target)
        return jsonify({"target": target, "results": results})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400