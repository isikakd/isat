import socket
from flask import current_app


def scan_port(target, port, timeout=1.5):
    """
    Tek bir portu kontrol eder ve durumunu döner.

    TCP "connect scan" yöntemi kullanılır: hedefe gerçek bir bağlantı
    denemesi yapılır. Bu, saldırı (exploitation) değildir — sadece
    bağlantının kurulup kurulamadığını kontrol eden standart bir
    bilgi toplama (information gathering) tekniğidir.

    Args:
        target (str): Hedef domain veya IP adresi.
        port (int): Kontrol edilecek port numarası.
        timeout (float): Bağlantı denemesi için saniye cinsinden zaman aşımı.

    Returns:
        str: "open", "closed" veya "filtered"
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # connect_ex, bağlantı hatasını exception fırlatmadan
        # bir hata koduyla (0 = başarılı) döndürür.
        result = sock.connect_ex((target, port))

        if result == 0:
            return "open"
        else:
            return "closed"

    except socket.timeout:
        # Zaman aşımı genelde bir firewall'un paketi sessizce
        # düşürdüğü (drop ettiği) anlamına gelir -> "filtered"
        return "filtered"

    except socket.gaierror:
        # DNS çözümlemesi başarısız oldu (geçersiz domain)
        raise ValueError(f"Hedef çözümlenemedi (DNS hatası): {target}")

    except OSError:
        return "filtered"

    finally:
        sock.close()


def scan_common_ports(target, ports=None, timeout=None):
    """
    Verilen hedef için yaygın portların tamamını tarar.

    Args:
        target (str): Hedef domain veya IP adresi.
        ports (list[int], optional): Taranacak port listesi.
            Verilmezse config.py'daki COMMON_PORTS kullanılır.
        timeout (float, optional): Her port için zaman aşımı.
            Verilmezse config.py'daki SCAN_TIMEOUT kullanılır.

    Returns:
        list[dict]: Her port için {"port": int, "status": str} sözlükleri.
    """
    if ports is None:
        ports = current_app.config["COMMON_PORTS"]
    if timeout is None:
        timeout = current_app.config["SCAN_TIMEOUT"]

    results = []
    for port in ports:
        status = scan_port(target, port, timeout)
        results.append({"port": port, "status": status})

    return results
