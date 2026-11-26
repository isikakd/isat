import re

# Basit domain formatı kontrolü (ör: example.com, sub.example.co.uk)
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# Basit IPv4 formatı kontrolü (ör: 8.8.8.8)
IPV4_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


def normalize_target(raw_target):
    """
    Kullanıcının sıkça yaptığı, aslında kötü niyetli olmayan ama ham
    haliyle validasyondan geçemeyecek girdileri (protokol öneki, sondaki
    path/slash, port numarası, baştaki/sondaki boşluk) temizler.

    Örnek: "https://example.com/path" -> "example.com"

    Bu fonksiyon güvenlik kontrolü YAPMAZ, yalnızca biçimsel bir ön
    temizlik yapar; asıl doğrulama hâlâ validate_target() içinde
    gerçekleşir. Amaç, kullanıcıyı gereksiz yere reddetmek yerine,
    yaygın ve zararsız yazım alışkanlıklarını tolere etmektir.
    """
    target = raw_target.strip()

    # Yaygın protokol öneklerini kaldır
    for prefix in ("https://", "http://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]
            break

    # Sondaki path'i kaldır (ör: "example.com/path" -> "example.com")
    target = target.split("/")[0]

    # Sondaki port numarasını kaldır (ör: "example.com:8080" -> "example.com").
    # IPv6 adresleriyle karışmaması için yalnızca tek ':' varsa uygularız.
    if target.count(":") == 1:
        target = target.split(":")[0]

    return target.strip()


def _is_valid_ipv4(value):
    """Bir string'in geçerli bir IPv4 adresi olup olmadığını kontrol eder."""
    match = IPV4_PATTERN.match(value)
    if not match:
        return False
    # Her oktetin 0-255 aralığında olduğunu doğrula
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def validate_target(target):
    """
    Kullanıcının girdiği hedefi (domain veya IP) doğrular.

    Bu fonksiyon, kullanıcıdan gelen ham veriyi güvenlik açısından
    riskli olabilecek (ör. komut enjeksiyonuna zemin hazırlayan özel
    karakterler içeren) bir girdi olarak ele alır ve yalnızca
    beklenen formattaki değerlerin işlenmesine izin verir.

    Args:
        target (str): Kullanıcının girdiği domain veya IP adresi.

    Returns:
        tuple[bool, str | None]: (Geçerli mi?, Hata mesajı ya da None)
    """
    if not target:
        return False, "Lütfen bir domain veya IP adresi girin."

    if len(target) > 253:
        return False, "Girilen değer çok uzun."

    # Sadece izin verilen karakterler: harf, rakam, nokta, tire
    if not re.match(r"^[A-Za-z0-9.-]+$", target):
        return False, "Geçersiz karakterler tespit edildi. Yalnızca harf, rakam, nokta ve tire kullanılabilir."

    if _is_valid_ipv4(target):
        return True, None

    if DOMAIN_PATTERN.match(target):
        return True, None

    return False, "Girilen değer geçerli bir domain veya IP adresi formatında değil."