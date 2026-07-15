import requests
from flask import current_app


def analyze_headers(target):
    """
    Hedefin HTTP response header'larını inceleyerek güvenlik
    başlıklarının (security headers) var olup olmadığını kontrol eder.

    Bu işlem bir saldırı değildir; sunucunun normal şartlarda herkese
    açık şekilde döndürdüğü HTTP header bilgisini okur (bilgi toplama).

    Args:
        target (str): Hedef domain veya IP adresi (şema olmadan, ör: "example.com").

    Returns:
        dict: {
            "reachable": bool,
            "url": str,           # fiilen istek atılan URL (http/https)
            "present": [str],     # bulunan güvenlik başlıkları
            "missing": [str],     # eksik güvenlik başlıkları
            "error": str | None
        }
    """
    required_headers = current_app.config["REQUIRED_HEADERS"]

    # Önce HTTPS deniyoruz, olmazsa HTTP'ye düşüyoruz (fallback).
    # Bu sıralama, SSL analizi adımıyla da tutarlı olacak.
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "ISAT-SecurityAssessment/1.0"}
            )

            present = []
            missing = []

            for header_name in required_headers:
                if header_name in response.headers:
                    present.append(header_name)
                else:
                    missing.append(header_name)

            return {
                "reachable": True,
                "url": url,
                "present": present,
                "missing": missing,
                "error": None
            }

        except requests.exceptions.SSLError:
            # HTTPS başarısız oldu, HTTP ile tekrar deneyeceğiz (döngü devam eder)
            continue
        except requests.exceptions.ConnectionError:
            # Bu şema ile bağlantı kurulamadı, diğer şemayı dene
            continue
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.RequestException:
            continue

    # Hem HTTPS hem HTTP başarısız oldu
    return {
        "reachable": False,
        "url": None,
        "present": [],
        "missing": required_headers,
        "error": "Hedefe HTTP/HTTPS üzerinden ulaşılamadı."
    }
