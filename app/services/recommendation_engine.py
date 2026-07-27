# Her eksik header için üretilecek öneri metni.
HEADER_RECOMMENDATIONS = {
    "Content-Security-Policy": "Enable a Content-Security-Policy (CSP) header to reduce the risk of XSS and data injection attacks.",
    "Strict-Transport-Security": "Enable HSTS (Strict-Transport-Security) to enforce HTTPS connections and prevent downgrade attacks.",
    "X-Frame-Options": "Set X-Frame-Options to prevent clickjacking attacks via iframe embedding.",
    "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks.",
    "Referrer-Policy": "Configure a Referrer-Policy header to control how much referrer information is leaked to other sites.",
    "Permissions-Policy": "Configure a Permissions-Policy header to restrict access to sensitive browser features (camera, microphone, geolocation, etc.).",
}

# Riskli açık portlar için üretilecek öneri metni.
RISKY_PORT_RECOMMENDATIONS = {
    21: "Disable the FTP service (port 21) or replace it with a secure alternative such as SFTP/FTPS, since FTP transmits credentials in plaintext.",
    23: "Disable Telnet (port 23) immediately and replace it with SSH, as Telnet transmits all traffic, including credentials, unencrypted.",
    3389: "Restrict RDP (port 3389) access to a VPN or trusted IP ranges only, and enforce strong authentication (e.g., MFA).",
    3306: "Restrict direct external access to the MySQL service (port 3306); database ports should not be exposed to the public internet.",
}


def generate_recommendations(port_results, header_results, ssl_results):
    """
    Toplanan bulgulara dayanarak somut güvenlik önerileri üretir.

    Args:
        port_results (list[dict]): scan_common_ports() çıktısı.
        header_results (dict): analyze_headers() çıktısı.
        ssl_results (dict): analyze_ssl() çıktısı.

    Returns:
        list[str]: Öncelik sırasına göre (en kritikten en aza) öneriler.
                    Hiçbir sorun bulunamazsa boş liste döner.
    """
    recommendations = []

    # --- SSL/HTTPS ile ilgili öneriler önce gelir (en kritik kategori) ---
    ssl_status = ssl_results.get("status")
    if ssl_status == "expired":
        recommendations.append(
            "Renew the SSL certificate immediately — it has already expired, exposing users to security warnings and MITM risks."
        )
    elif ssl_status == "expiring_soon":
        days = ssl_results.get("days_remaining")
        recommendations.append(
            f"Renew the SSL certificate soon — it will expire in {days} day(s)."
        )
    elif ssl_status == "unavailable":
        recommendations.append(
            "Enable HTTPS with a valid SSL/TLS certificate; the target does not currently support a secure connection."
        )

    # --- Riskli açık portlarla ilgili öneriler ---
    for port_info in port_results:
        port_number = port_info.get("port")
        if port_info.get("status") == "open" and port_number in RISKY_PORT_RECOMMENDATIONS:
            recommendations.append(RISKY_PORT_RECOMMENDATIONS[port_number])

    # --- Eksik HTTP güvenlik başlıklarıyla ilgili öneriler ---
    if header_results.get("reachable"):
        for header_name in header_results.get("missing", []):
            if header_name in HEADER_RECOMMENDATIONS:
                recommendations.append(HEADER_RECOMMENDATIONS[header_name])

    # --- Genel bir kapanış önerisi (her zaman iyi bir pratik) ---
    if not recommendations:
        recommendations.append(
            "No critical issues were identified. Continue to monitor the target periodically and keep all software up to date."
        )
    else:
        recommendations.append(
            "Conduct periodic security assessments and restrict any unused services or ports exposed to the internet."
        )

    return recommendations
