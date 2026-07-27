import socket
import ssl
from datetime import datetime, timezone


# Sertifikadaki tarihler bu formatta gelir, ör: "Jun  9 12:00:00 2026 GMT"
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def _parse_cert_date(date_str):
    """Sertifikadan gelen tarih string'ini datetime nesnesine çevirir."""
    return datetime.strptime(date_str, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)


def analyze_ssl(target, port=443, timeout=5):
    """
    Hedefin HTTPS portunda (varsayılan 443) sunduğu SSL/TLS sertifikasını
    inceleyip issuer, geçerlilik tarihleri ve durum bilgisini döner.

    Bu işlem, sunucunun herkese açık şekilde sunduğu sertifika bilgisini
    okur; herhangi bir istismar veya saldırı içermez.

    Args:
        target (str): Hedef domain (IP adresleri için sertifika doğrulaması
            genelde anlamlı olmaz, çünkü sertifikalar domain adına verilir).
        port (int): SSL/TLS portu, varsayılan 443.
        timeout (float): Bağlantı zaman aşımı süresi.

    Returns:
        dict: {
            "has_ssl": bool,
            "issuer": str | None,
            "valid_from": str | None,
            "valid_until": str | None,
            "days_remaining": int | None,
            "status": str,   # "valid" | "expiring_soon" | "expired" | "unavailable"
            "error": str | None
        }
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()

        # Issuer bilgisi, iç içe tuple'lar şeklinde gelir; okunabilir bir
        # metne çeviriyoruz (ör: "Let's Encrypt")
        issuer_fields = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_fields.get("organizationName") or issuer_fields.get("commonName") or "Bilinmiyor"

        valid_from = _parse_cert_date(cert["notBefore"])
        valid_until = _parse_cert_date(cert["notAfter"])

        now = datetime.now(timezone.utc)
        days_remaining = (valid_until - now).days

        if days_remaining < 0:
            status = "expired"
        elif days_remaining <= 15:
            status = "expiring_soon"
        else:
            status = "valid"

        return {
            "has_ssl": True,
            "issuer": issuer,
            "valid_from": valid_from.strftime("%Y-%m-%d"),
            "valid_until": valid_until.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "status": status,
            "error": None
        }

    except socket.timeout:
        return _unavailable_result("Bağlantı zaman aşımına uğradı.")
    except socket.gaierror:
        return _unavailable_result("Hedef çözümlenemedi (DNS hatası).")
    except ssl.SSLCertVerificationError as e:
        return _unavailable_result(f"Sertifika doğrulanamadı: {e}")
    except (ssl.SSLError, ConnectionRefusedError, OSError) as e:
        return _unavailable_result(f"HTTPS/SSL bağlantısı kurulamadı: {e}")


def _unavailable_result(error_message):
    """SSL bilgisi alınamadığında döndürülecek standart sonuç yapısı."""
    return {
        "has_ssl": False,
        "issuer": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "status": "unavailable",
        "error": error_message
    }
