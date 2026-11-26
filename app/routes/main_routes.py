import os
from flask import Blueprint, render_template, request, jsonify, current_app, send_file
from app.services.port_scanner import scan_common_ports
from app.services.header_analyzer import analyze_headers
from app.services.ssl_analyzer import analyze_ssl
from app.services.dns_analyzer import get_dns_records
from app.services.whois_analyzer import get_whois_info
from app.services.risk_scorer import calculate_risk_score
from app.services.recommendation_engine import generate_recommendations
from app.services.report_generator import generate_pdf_report, build_report_filename
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

    # SSL sertifika analizi de diğer analizlerden bağımsız çalışır.
    try:
        ssl_results = analyze_ssl(target)
    except Exception:
        ssl_results = {
            "has_ssl": False,
            "issuer": None,
            "valid_from": None,
            "valid_until": None,
            "days_remaining": None,
            "status": "unavailable",
            "error": "SSL analizi sırasında beklenmeyen bir hata oluştu."
        }

    # DNS kayıtlarını sorgula. IP adresi girildiyse bu adım anlamlı
    # sonuç vermeyebilir; o durumda tüm kayıtlar boş dönecektir.
    try:
        dns_results = get_dns_records(target)
    except ValueError as e:
        dns_results = {"error": str(e)}
    except Exception:
        dns_results = {"error": "DNS sorgusu sırasında beklenmeyen bir hata oluştu."}

    # WHOIS bilgisi de diğer analizlerden bağımsız çalışır.
    try:
        whois_results = get_whois_info(target)
    except Exception:
        whois_results = {
            "available": False,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "error": "WHOIS analizi sırasında beklenmeyen bir hata oluştu."
        }

    # Risk skoru, önceki analizlerin (port, header, SSL) sonuçlarına
    # dayanır; bu yüzden diğer tüm analizlerden sonra hesaplanır.
    try:
        risk_results = calculate_risk_score(port_results, header_results, ssl_results)
    except Exception:
        risk_results = {"score": 0, "level": "low", "breakdown": []}

    # Öneriler de aynı bulgulara dayanır, risk skoruyla aynı girdileri kullanır.
    try:
        recommendations = generate_recommendations(port_results, header_results, ssl_results)
    except Exception:
        recommendations = []

    return jsonify({
        "target": target,
        "ports": port_results,
        "headers": header_results,
        "ssl": ssl_results,
        "dns": dns_results,
        "whois": whois_results,
        "risk": risk_results,
        "recommendations": recommendations
    })


@main_bp.route("/report", methods=["POST"])
def report():
    """
    Bir tarama sonucundan (frontend'in daha önce /scan'den aldığı JSON'u
    geri gönderir) PDF rapor üretir ve indirme için döner.

    Not: Taramayı burada tekrar çalıştırmıyoruz — kullanıcı zaten dashboard'da
    bir tarama yaptı, o sonucu tekrar sunucuya göndererek raporu üretiyoruz.
    Bu, aynı taramanın iki kez (bir kez ekrana, bir kez PDF için) çalışmasını
    önler.
    """
    scan_data = request.get_json(silent=True)

    if not scan_data or "target" not in scan_data:
        return jsonify({"error": "Geçerli bir tarama verisi bulunamadı."}), 400

    try:
        filename = build_report_filename(scan_data["target"])
        output_path = os.path.join(current_app.config["REPORTS_DIR"], filename)
        generate_pdf_report(scan_data, output_path)

        return send_file(
            output_path,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf"
        )
    except Exception:
        return jsonify({"error": "PDF rapor oluşturulurken bir hata oluştu."}), 500