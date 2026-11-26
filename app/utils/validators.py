import re

# Basit domain formatı kontrolü (ör: example.com, sub.example.co.uk)
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# Basit IPv4 formatı kontrolü (ör: 8.8.8.8)
IPV4_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


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
