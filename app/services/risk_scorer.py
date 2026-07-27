# Risk puanlama kuralları. Her kural, bulgunun ne kadar riskli olduğuna
# dair bir ağırlık (puan) taşır. Bu değerler config.py'ye taşınabilir,
# ama okunabilirlik için burada, servisin yanında tutuyoruz.

HEADER_WEIGHTS = {
    "Content-Security-Policy": 10,
    "Strict-Transport-Security": 15,
    "X-Frame-Options": 8,
    "X-Content-Type-Options": 5,
    "Referrer-Policy": 5,
    "Permissions-Policy": 5,
}

# Yüksek riskli olarak kabul edilen açık portlar ve puan ağırlıkları.
# FTP (21) ve Telnet (23), şifrelenmemiş protokoller olduğu ve genellikle
# eski/güvensiz servisleri işaret ettiği için yüksek puanlıdır.
RISKY_PORT_WEIGHTS = {
    21: ("FTP", 20),
    23: ("Telnet", 30),
    3389: ("RDP", 20),
    3306: ("MySQL", 15),
}

SSL_EXPIRED_WEIGHT = 30
SSL_EXPIRING_SOON_WEIGHT = 10

MAX_SCORE = 100


def calculate_risk_score(port_results, header_results, ssl_results):
    """
    Toplanan bulgulara dayanarak bir risk skoru (0-100) ve skora katkı
    veren bulguların listesini (breakdown) hesaplar.

    Args:
        port_results (list[dict]): scan_common_ports() çıktısı.
        header_results (dict): analyze_headers() çıktısı.
        ssl_results (dict): analyze_ssl() çıktısı.

    Returns:
        dict: {
            "score": int,          # 0-100 arası, üst sınırla sınırlandırılmış
            "level": str,          # "low" | "medium" | "high"
            "breakdown": [str],    # skora katkı veren her bulgunun açıklaması
        }
    """
    score = 0
    breakdown = []

    # --- Eksik HTTP güvenlik başlıkları ---
    missing_headers = header_results.get("missing", []) if header_results.get("reachable") else []
    for header_name in missing_headers:
        weight = HEADER_WEIGHTS.get(header_name, 5)
        score += weight
        breakdown.append(f"Missing {header_name} (+{weight})")

    # --- Riskli açık portlar ---
    for port_info in port_results:
        port_number = port_info.get("port")
        if port_info.get("status") == "open" and port_number in RISKY_PORT_WEIGHTS:
            service_name, weight = RISKY_PORT_WEIGHTS[port_number]
            score += weight
            breakdown.append(f"{service_name} Open (port {port_number}) (+{weight})")

    # --- SSL sertifika durumu ---
    ssl_status = ssl_results.get("status")
    if ssl_status == "expired":
        score += SSL_EXPIRED_WEIGHT
        breakdown.append(f"Expired SSL Certificate (+{SSL_EXPIRED_WEIGHT})")
    elif ssl_status == "expiring_soon":
        score += SSL_EXPIRING_SOON_WEIGHT
        breakdown.append(f"SSL Certificate Expiring Soon (+{SSL_EXPIRING_SOON_WEIGHT})")
    elif ssl_status == "unavailable":
        # HTTPS hiç desteklenmiyorsa bu da başlı başına bir risktir
        score += 15
        breakdown.append("No HTTPS / SSL Unavailable (+15)")

    # Skoru 0-100 aralığında sınırlandır (birden fazla riskli bulgu
    # toplamda 100'ü aşabilir, bu durumda üst sınıra sabitliyoruz)
    score = min(score, MAX_SCORE)

    if score <= 20:
        level = "low"
    elif score <= 50:
        level = "medium"
    else:
        level = "high"

    return {
        "score": score,
        "level": level,
        "breakdown": breakdown
    }
