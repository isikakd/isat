import dns.resolver
import dns.exception


# Sorgulanacak kayıt tipleri
RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS"]

# Bazı yerel ağlarda (router/ISP DNS sunucusu) belirli kayıt tipleri
# (özellikle NS) zaman aşımına uğrayabiliyor. Bu durumda herkese açık,
# güvenilir bir DNS sunucusuna (Google Public DNS) yedek olarak geçiyoruz.
FALLBACK_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]


def _query_record(resolver, target, record_type):
    """
    Tek bir DNS kayıt tipini sorgular ve okunabilir string listesine çevirir.

    Sistemin varsayılan DNS sunucusu zaman aşımına uğrarsa, herkese açık
    bir DNS sunucusuyla (fallback) tekrar denenir. Bu, ev/ofis ağlarındaki
    bazı router'ların NS gibi daha az yaygın sorgu tiplerinde yaşadığı
    performans sorunlarına karşı servisi daha dayanıklı hale getirir.

    Returns:
        list[str]: Bulunan kayıtların metin karşılıkları. Kayıt yoksa boş liste.
    """
    try:
        answer = resolver.resolve(target, record_type)
        return _format_answer(answer, record_type)

    except dns.resolver.NoAnswer:
        # Bu kayıt tipi için hiçbir kayıt yok (hata değil, normal bir durum)
        return []
    except dns.resolver.NXDOMAIN:
        # Domain'in kendisi mevcut değil; bunu üst seviyede ele alacağız
        raise ValueError(f"Domain bulunamadı: {target}")
    except Exception:
        # Zaman aşımı, "NoNameservers" veya başka herhangi bir DNS hatası
        # olabilir — sebebi ne olursa olsun, sistemin varsayılan DNS
        # sunucusu bu sorguyu yanıtlayamadıysa, herkese açık bir DNS
        # sunucusuyla (fallback) tekrar deniyoruz.
        return _query_with_fallback(target, record_type)


def _query_with_fallback(target, record_type):
    """Herkese açık bir DNS sunucusu (8.8.8.8 / 1.1.1.1) ile tekrar dener."""
    fallback_resolver = dns.resolver.Resolver(configure=False)
    fallback_resolver.nameservers = FALLBACK_DNS_SERVERS
    fallback_resolver.timeout = 3
    fallback_resolver.lifetime = 3

    try:
        answer = fallback_resolver.resolve(target, record_type)
        return _format_answer(answer, record_type)
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        # Fallback de başarısız olursa, kullanıcıyı bilgilendirmek yerine
        # bu kayıt tipini boş olarak işaretliyoruz (diğer kayıtlar etkilenmesin)
        return []


def _format_answer(answer, record_type):
    """DNS yanıtını (rdata listesi) okunabilir string listesine çevirir."""
    records = []
    for rdata in answer:
        if record_type == "MX":
            # MX kayıtları öncelik (preference) değeri de taşır
            records.append(f"{rdata.exchange} (priority: {rdata.preference})")
        elif record_type == "TXT":
            # TXT kayıtları byte-string parçaları halinde gelir, birleştiriyoruz
            txt_value = b"".join(rdata.strings).decode("utf-8", errors="replace")
            records.append(txt_value)
        else:
            records.append(str(rdata))
    return records


def get_dns_records(target):
    """
    Bir domain için A, AAAA, MX, TXT ve NS kayıtlarının tamamını sorgular.

    Args:
        target (str): Hedef domain adı (IP adresleri için DNS sorgusu
            anlamlı değildir, bu durumda tüm kayıtlar boş dönecektir).

    Returns:
        dict: {"A": [...], "AAAA": [...], "MX": [...], "TXT": [...], "NS": [...]}
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    results = {}
    for record_type in RECORD_TYPES:
        results[record_type] = _query_record(resolver, target, record_type)

    return results