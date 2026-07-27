import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    ListFlowable, ListItem, KeepTogether
)


# Risk seviyesine göre renk (PDF içindeki risk skoru satırını renklendirmek için)
RISK_LEVEL_COLORS = {
    "low": colors.HexColor("#1e8e4e"),
    "medium": colors.HexColor("#b06f00"),
    "high": colors.HexColor("#c62828"),
}


def _build_styles():
    """Rapor için kullanılacak paragraf stillerini tanımlar."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ISATTitle",
        fontSize=20,
        leading=24,
        spaceAfter=6,
        textColor=colors.HexColor("#0d1117"),
    ))

    styles.add(ParagraphStyle(
        name="ISATSectionHeader",
        fontSize=13,
        leading=16,
        spaceBefore=16,
        spaceAfter=8,
        textColor=colors.HexColor("#0d1117"),
        borderPadding=0,
    ))

    styles.add(ParagraphStyle(
        name="ISATBody",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#333333"),
    ))

    return styles


def _simple_table(data_rows, col_widths=None):
    """Basit, iki sütunlu (etiket/değer) tablolar için ortak stil üretir."""
    # repeatRows=1: tablo bir sayfa sonunda bölünürse, başlık satırı
    # (ilk satır) yeni sayfada da tekrar gösterilir. Bu, uzun tabloların
    # (örn. 13 satırlık port tablosu) sayfa geçişinde okunabilirliğini korur.
    table = Table(data_rows, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#222222")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9ecef")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def generate_pdf_report(scan_data, output_path):
    """
    Bir taramanın tüm sonuçlarını profesyonel görünümlü bir PDF rapora dönüştürür.

    Args:
        scan_data (dict): /scan endpoint'inin döndürdüğü tam sonuç sözlüğü
            (target, ports, headers, ssl, dns, whois, risk, recommendations).
        output_path (str): Oluşturulacak PDF dosyasının tam yolu.

    Returns:
        str: Oluşturulan PDF dosyasının yolu (output_path ile aynı).
    """
    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
    )

    elements = []

    # --- Başlık ve genel bilgiler ---
    elements.append(Paragraph("Internal Security Assessment Report", styles["ISATTitle"]))
    elements.append(Paragraph(f"<b>Target:</b> {scan_data.get('target', '-')}", styles["ISATBody"]))
    elements.append(Paragraph(
        f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["ISATBody"]
    ))
    elements.append(Spacer(1, 12))

    # --- Risk Skoru ---
    risk = scan_data.get("risk", {})
    risk_level = risk.get("level", "low")
    risk_color = RISK_LEVEL_COLORS.get(risk_level, colors.black)

    elements.append(Paragraph("Risk Score", styles["ISATSectionHeader"]))
    elements.append(Paragraph(
        f"<font color='{risk_color.hexval()}'><b>{risk.get('score', 0)} / 100 "
        f"({risk_level.upper()} RISK)</b></font>",
        styles["ISATBody"]
    ))
    if risk.get("breakdown"):
        bullet_items = [
            ListItem(Paragraph(item, styles["ISATBody"]), leftIndent=10)
            for item in risk["breakdown"]
        ]
        elements.append(ListFlowable(bullet_items, bulletType="bullet", start="circle"))
    elements.append(Spacer(1, 8))

    # --- Security Recommendations ---
    elements.append(Paragraph("Security Recommendations", styles["ISATSectionHeader"]))
    recommendations = scan_data.get("recommendations", [])
    if recommendations:
        rec_items = [
            ListItem(Paragraph(rec, styles["ISATBody"]), leftIndent=10)
            for rec in recommendations
        ]
        elements.append(ListFlowable(rec_items, bulletType="bullet", start="circle"))
    else:
        elements.append(Paragraph("No recommendations available.", styles["ISATBody"]))
    elements.append(Spacer(1, 8))

    # --- Port Scan Results ---
    port_section = [Paragraph("Port Scan Results", styles["ISATSectionHeader"])]
    port_rows = [["Port", "Status"]]
    for p in scan_data.get("ports", []):
        port_rows.append([str(p.get("port")), p.get("status", "-")])
    port_section.append(_simple_table(port_rows, col_widths=[3 * cm, 3 * cm]))
    # KeepTogether: bu bölümün başlığı ve tablosu, mümkünse aynı sayfada
    # kalır; sayfa sonuna denk gelirse tamamı bir sonraki sayfaya kayar,
    # satırların ortadan bölünüp iç içe görünmesi engellenir.
    elements.append(KeepTogether(port_section))
    elements.append(Spacer(1, 8))

    # --- HTTP Security Headers ---
    elements.append(Paragraph("HTTP Security Headers", styles["ISATSectionHeader"]))
    headers = scan_data.get("headers", {})
    if headers.get("reachable"):
        header_rows = [["Header", "Status"]]
        for h in headers.get("present", []):
            header_rows.append([h, "Present"])
        for h in headers.get("missing", []):
            header_rows.append([h, "Missing"])
        elements.append(_simple_table(header_rows, col_widths=[8 * cm, 3 * cm]))
    else:
        elements.append(Paragraph(
            headers.get("error") or "Target unreachable over HTTP/HTTPS.", styles["ISATBody"]
        ))
    elements.append(Spacer(1, 8))

    # --- SSL Certificate ---
    elements.append(Paragraph("SSL Certificate", styles["ISATSectionHeader"]))
    ssl_info = scan_data.get("ssl", {})
    if ssl_info.get("has_ssl"):
        ssl_rows = [
            ["Field", "Value"],
            ["Issuer", ssl_info.get("issuer", "-")],
            ["Valid From", ssl_info.get("valid_from", "-")],
            ["Expiration Date", ssl_info.get("valid_until", "-")],
            ["Days Remaining", str(ssl_info.get("days_remaining", "-"))],
            ["Status", ssl_info.get("status", "-").upper()],
        ]
        elements.append(_simple_table(ssl_rows, col_widths=[5 * cm, 6 * cm]))
    else:
        elements.append(Paragraph(
            ssl_info.get("error") or "SSL certificate information unavailable.", styles["ISATBody"]
        ))
    elements.append(Spacer(1, 8))

    # --- DNS Information ---
    elements.append(Paragraph("DNS Information", styles["ISATSectionHeader"]))
    dns_info = scan_data.get("dns", {})
    if "error" in dns_info:
        elements.append(Paragraph(dns_info["error"], styles["ISATBody"]))
    else:
        dns_rows = [["Record Type", "Values"]]
        for record_type in ["A", "AAAA", "MX", "TXT", "NS"]:
            values = dns_info.get(record_type, [])
            value_text = "<br/>".join(values) if values else "No records found"
            dns_rows.append([record_type, Paragraph(value_text, styles["ISATBody"])])
        elements.append(_simple_table(dns_rows, col_widths=[3 * cm, 8 * cm]))
    elements.append(Spacer(1, 8))

    # --- WHOIS Information ---
    elements.append(Paragraph("WHOIS Information", styles["ISATSectionHeader"]))
    whois_info = scan_data.get("whois", {})
    if whois_info.get("available"):
        ns_text = "<br/>".join(whois_info.get("name_servers", [])) or "-"
        whois_rows = [
            ["Field", "Value"],
            ["Registrar", whois_info.get("registrar") or "-"],
            ["Creation Date", whois_info.get("creation_date") or "-"],
            ["Expiration Date", whois_info.get("expiration_date") or "-"],
            ["Updated Date", whois_info.get("updated_date") or "-"],
            ["Name Servers", Paragraph(ns_text, styles["ISATBody"])],
        ]
        elements.append(_simple_table(whois_rows, col_widths=[5 * cm, 6 * cm]))
    else:
        elements.append(Paragraph(
            whois_info.get("error") or "WHOIS information unavailable.", styles["ISATBody"]
        ))

    doc.build(elements)
    return output_path


def build_report_filename(target):
    """Hedef ve zaman damgasına dayalı, güvenli bir dosya adı üretir."""
    safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"ISAT_Report_{safe_target}_{timestamp}.pdf"