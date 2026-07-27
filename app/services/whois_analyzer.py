import whois
from datetime import datetime


def _normalize_date(value):
    """
    python-whois bazen tek bir datetime, bazen de bir liste (birden fazla
    kaynak sunucudan gelen farklı tarih) döndürebilir. Bu fonksiyon,
    her iki durumu da tek bir okunabilir string'e normalize eder.
    """
    if value is None:
        return None

    if isinstance(value, list):
        # Liste geldiyse ilk (genelde en güvenilir) tarihi al
        value = value[0] if value else None

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")

    if isinstance(value, str):
        return value

    return str(value)


def _normalize_name_servers(value):
    """Name server bilgisini her zaman bir liste olarak döner."""
    if value is None:
        return []

    if isinstance(value, list):
        # Bazı registrar'lar aynı name server'ı büyük/küçük harf farkıyla
        # birden çok kez döndürebilir; tekrarları temizliyoruz.
        cleaned = sorted(set(ns.lower() for ns in value if ns))
        return cleaned

    return [str(value).lower()]


def get_whois_info(target):
    """
    Bir domain için WHOIS bilgilerini sorgular.

    Bu işlem, ICANN ve registrar'lar tarafından herkese açık şekilde
    sunulan kayıt bilgilerini okur; herhangi bir istismar içermez.

    Not: WHOIS sorgusu yalnızca domain adları için anlamlıdır; IP
    adresleri için farklı bir protokol (RDAP/IP WHOIS) gerekir ve
    bu kapsamın dışındadır.

    Args:
        target (str): Hedef domain adı.

    Returns:
        dict: {
            "available": bool,
            "registrar": str | None,
            "creation_date": str | None,
            "expiration_date": str | None,
            "updated_date": str | None,
            "name_servers": list[str],
            "error": str | None
        }
    """
    try:
        # timeout parametresi, WHOIS sunucusu yanıt vermediğinde
        # servisin sonsuza kadar beklemesini önler.
        w = whois.whois(target, timeout=7)

        # Bazı domainlerde (özellikle gizlilik korumalı olanlarda) WHOIS
        # sunucusu boş bir yanıt döndürebilir; bunu da "bulunamadı" sayıyoruz.
        if not w or not w.domain_name:
            return _unavailable_result("WHOIS kaydı bulunamadı.")

        return {
            "available": True,
            "registrar": w.registrar,
            "creation_date": _normalize_date(w.creation_date),
            "expiration_date": _normalize_date(w.expiration_date),
            "updated_date": _normalize_date(w.updated_date),
            "name_servers": _normalize_name_servers(w.name_servers),
            "error": None
        }

    except Exception as e:
        return _unavailable_result(f"WHOIS sorgusu başarısız oldu: {e}")


def _unavailable_result(error_message):
    """WHOIS bilgisi alınamadığında döndürülecek standart sonuç yapısı."""
    return {
        "available": False,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "error": error_message
    }
