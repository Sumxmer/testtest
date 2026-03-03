# ==============================
# PDF Report Generator
# ==============================
from fpdf import FPDF

class CosvinteReport(FPDF):
    """
    Custom PDF class สำหรับ COSVINTE Report
    การ inherit จาก FPDF ทำให้เราสามารถ override
    header() และ footer() ที่จะถูกเรียกอัตโนมัติทุกหน้าได้
    """

    # สี Palette สำหรับ Report (RGB)
    COLOR_DARK_BG   = (15,  20,  40)   # พื้นหลังเข้ม (cover page)
    COLOR_ACCENT    = (0,   200, 255)   # สีฟ้า Cyan สำหรับหัวข้อ
    COLOR_CRITICAL  = (220, 30,  30)    # สีแดงสำหรับ CRITICAL
    COLOR_HIGH      = (220, 80,  20)    # สีส้มสำหรับ HIGH
    COLOR_MEDIUM    = (200, 160, 0)     # สีเหลืองสำหรับ MEDIUM
    COLOR_LOW       = (50,  160, 50)    # สีเขียวสำหรับ LOW
    COLOR_TEXT      = (30,  30,  30)    # สีข้อความหลัก
    COLOR_SUBTEXT   = (80,  80,  100)   # สีข้อความรอง
    COLOR_TABLE_HDR = (30,  40,  80)    # สีหัวตาราง
    COLOR_ROW_ALT   = (240, 242, 248)   # สีสลับแถวตาราง

    def __init__(self):
        # orientation='P' = Portrait, unit='mm', format='A4'
        super().__init__(orientation='P', unit='mm', format='A4')
        self.set_auto_page_break(auto=True, margin=20)
        self._page_num_visible = True  # ซ่อน footer ใน cover page

    # --------------------------------------------------
    # Header: แสดงทุกหน้า (ยกเว้น cover page)
    # --------------------------------------------------
    def header(self):
        # หน้าแรก (cover) ไม่ต้องมี header bar
        if self.page_no() == 1:
            return

        # วาด Header Bar สีเข้มด้านบน
        self.set_fill_color(*self.COLOR_DARK_BG)
        self.rect(0, 0, 210, 14, style='F')

        # ชื่อ Tool ด้านซ้าย
        self.set_font("Helvetica", style='B', size=8)
        self.set_text_color(*self.COLOR_ACCENT)
        self.set_xy(10, 4)
        self.cell(0, 6, "COSVINTE — Linux Capability Security Report", align='L')

        # วันที่ด้านขวา
        self.set_text_color(150, 150, 170)
        self.set_xy(0, 4)
        self.cell(200, 6, datetime.now().strftime("%Y-%m-%d"), align='R')

        # เส้น Separator ใต้ header
        self.set_draw_color(*self.COLOR_ACCENT)
        self.set_line_width(0.4)
        self.line(0, 14, 210, 14)
        self.ln(8)  # เว้นช่องว่างหลัง header

    # --------------------------------------------------
    # Footer: แสดงทุกหน้า (ยกเว้น cover page)
    # --------------------------------------------------
    def footer(self):
        if self.page_no() == 1:
            return

        self.set_y(-14)

        # เส้น separator เหนือ footer
        self.set_draw_color(*self.COLOR_ACCENT)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(1)

        # ข้อความ Confidential ด้านซ้าย
        self.set_font("Helvetica", style='I', size=7)
        self.set_text_color(150, 150, 150)
        self.set_x(10)
        self.cell(95, 5, "CONFIDENTIAL — For Authorized Personnel Only", align='L')

        # เลขหน้าด้านขวา
        self.cell(95, 5, f"Page {self.page_no()}", align='R')

    # --------------------------------------------------
    # Helper: วาดกล่องสี Severity Badge
    # --------------------------------------------------
    def severity_color(self, sev: str) -> tuple:
        """คืนค่าสี RGB ตามระดับ Severity"""
        return {
            "CRITICAL": self.COLOR_CRITICAL,
            "HIGH":     self.COLOR_HIGH,
            "MEDIUM":   self.COLOR_MEDIUM,
            "LOW":      self.COLOR_LOW,
        }.get(sev, (100, 100, 100))

    def draw_severity_badge(self, x: float, y: float, sev: str):
        """วาด Badge สี่เหลี่ยมมุมโค้งพร้อมข้อความ Severity"""
        color = self.severity_color(sev)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", style='B', size=8)
        # วาดกล่องสี่เหลี่ยม
        self.set_xy(x, y)
        self.cell(22, 6, f" {sev} ", align='C', fill=True)
        # Reset สีข้อความ
        self.set_text_color(*self.COLOR_TEXT)

    # --------------------------------------------------
    # Helper: วาด CVSS Score Bar แบบ Graphic
    # --------------------------------------------------
    def draw_cvss_bar(self, x: float, y: float, score: float, bar_w: float = 50):
        """
        วาด Progress Bar แสดง CVSS Score
        ตรรกะ: คำนวณสัดส่วน score/10 แล้วคูณด้วยความกว้าง Bar
        """
        filled_w = (score / 10.0) * bar_w

        # Background bar (สีเทาอ่อน)
        self.set_fill_color(220, 220, 230)
        self.rect(x, y, bar_w, 4, style='F')

        # Filled bar (สีตาม score)
        if score >= 9:    fill_color = self.COLOR_CRITICAL
        elif score >= 7:  fill_color = self.COLOR_HIGH
        elif score >= 4:  fill_color = self.COLOR_MEDIUM
        else:             fill_color = self.COLOR_LOW
        self.set_fill_color(*fill_color)
        self.rect(x, y, filled_w, 4, style='F')

        # ข้อความตัวเลข Score ด้านขวา Bar
        self.set_font("Helvetica", style='B', size=8)
        self.set_text_color(*fill_color)
        self.set_xy(x + bar_w + 2, y - 1)
        self.cell(12, 6, f"{score:.1f}", align='L')
        self.set_text_color(*self.COLOR_TEXT)

    # --------------------------------------------------
    # Helper: Section Header (หัวข้อแต่ละส่วน)
    # --------------------------------------------------
    def section_header(self, title: str, section_num: int = None):
        """วาดหัวข้อ Section พร้อมเส้นขีดด้านล่าง"""
        self.ln(4)

        # แถบสีด้านซ้าย (accent bar)
        bar_y = self.get_y()
        self.set_fill_color(*self.COLOR_ACCENT)
        self.rect(10, bar_y, 2, 8, style='F')

        # ชื่อ Section
        self.set_font("Helvetica", style='B', size=13)
        self.set_text_color(*self.COLOR_DARK_BG)
        self.set_x(15)
        prefix = f"{section_num:02d}. " if section_num else ""
        self.cell(0, 8, f"{prefix}{title.upper()}", align='L')
        self.ln(2)

        # เส้นขีดใต้หัวข้อ
        self.set_draw_color(*self.COLOR_ACCENT)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

        # Reset สี
        self.set_text_color(*self.COLOR_TEXT)

    # --------------------------------------------------
    # Helper: กล่องข้อความ Highlighted (Info Box)
    # --------------------------------------------------
    def info_box(self, text: str, box_color: tuple = None, text_color: tuple = None):
        """วาดกล่องข้อความพื้นหลังสี เช่น Warning Box, Info Box"""
        if box_color is None:
            box_color = (240, 244, 255)
        if text_color is None:
            text_color = self.COLOR_TEXT

        x = self.get_x()
        y = self.get_y()
        w = 190 - x + 10  # ความกว้างเต็ม margin

        # วาดพื้นหลัง
        self.set_fill_color(*box_color)
        # คำนวณความสูงของ Box จากข้อความ (approximate)
        lines_needed = max(1, len(text) // 90 + 1)
        box_h = lines_needed * 5 + 6
        self.rect(10, y, 190, box_h, style='F')

        # ขอบด้านซ้าย
        self.set_fill_color(*self.COLOR_ACCENT)
        self.rect(10, y, 1.5, box_h, style='F')

        # ข้อความ
        self.set_font("Helvetica", size=9)
        self.set_text_color(*text_color)
        self.set_xy(14, y + 3)
        self.multi_cell(184, 5, text)
        self.set_text_color(*self.COLOR_TEXT)
        self.ln(2)


# ==============================
# Page Builder Functions
# ==============================

def build_cover_page(pdf: CosvinteReport, findings: list, mode_label: str):
    """
    สร้างหน้าปก (Cover Page) สไตล์ Dark Cybersecurity Report
    แนวคิด: หน้าปกคือ 'First Impression' ของรายงาน ต้องดูเป็นมืออาชีพ
    """
    pdf.add_page()

    # ── พื้นหลังสีเข้มครึ่งบน ──
    pdf.set_fill_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.rect(0, 0, 210, 140, style='F')

    # ── Logo / Tool Name ──
    pdf.set_font("Helvetica", style='B', size=36)
    pdf.set_text_color(*CosvinteReport.COLOR_ACCENT)
    pdf.set_xy(0, 35)
    pdf.cell(210, 15, "COSVINTE", align='C')

    # ── Tagline ──
    pdf.set_font("Helvetica", style='I', size=12)
    pdf.set_text_color(160, 170, 200)
    pdf.set_xy(0, 52)
    pdf.cell(210, 8, "Linux Capability Vulnerability Scanner", align='C')

    # ── เส้น Divider สีฟ้า ──
    pdf.set_draw_color(*CosvinteReport.COLOR_ACCENT)
    pdf.set_line_width(0.8)
    pdf.line(50, 64, 160, 64)

    # ── Report Title ──
    pdf.set_font("Helvetica", style='B', size=16)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(0, 68)
    pdf.cell(210, 10, "SECURITY ASSESSMENT REPORT", align='C')

    # ── Overall Risk Score Badge (ใหญ่ๆ) ──
    max_score = max((f["risk_score"] for f in findings), default=0)
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")

    # วาดกล่อง Overall Risk
    overall_sev = ("CRITICAL" if max_score >= 9 else
                   "HIGH"     if max_score >= 7 else
                   "MEDIUM"   if max_score >= 4 else "LOW")
    sev_color = CosvinteReport().__class__.__dict__  # จะใช้วิธีอื่น
    color_map = {
        "CRITICAL": (220, 30, 30), "HIGH": (220, 80, 20),
        "MEDIUM": (200, 160, 0),   "LOW": (50, 160, 50),
    }
    risk_color = color_map[overall_sev]

    # กล่องกลมๆ สำหรับ Overall Risk
    pdf.set_fill_color(*risk_color)
    pdf.rect(75, 85, 60, 20, style='F')
    pdf.set_font("Helvetica", style='B', size=11)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(75, 87)
    pdf.cell(60, 8, f"OVERALL RISK: {overall_sev}", align='C')
    pdf.set_xy(75, 94)
    pdf.cell(60, 6, f"Score: {max_score:.1f} / 10.0", align='C')

    # ── ครึ่งล่าง: ข้อมูล Meta ──
    pdf.set_text_color(*CosvinteReport.COLOR_TEXT)

    # กล่อง System Info
    info_y = 148
    pdf.set_font("Helvetica", style='B', size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)

    meta_items = [
        ("Target System",  platform.node()),
        ("Operating System", get_distro()),
        ("Architecture",   platform.machine()),
        ("Scan Mode",      mode_label),
        ("Report Date",    datetime.now().strftime("%B %d, %Y — %H:%M UTC")),
        ("Generated By",   "COSVINTE v1.0 | Capability Scanner"),
    ]

    for i, (label, value) in enumerate(meta_items):
        row_y = info_y + (i * 11)
        # สีสลับแถว
        if i % 2 == 0:
            pdf.set_fill_color(245, 247, 252)
            pdf.rect(10, row_y - 1, 190, 10, style='F')

        pdf.set_font("Helvetica", style='B', size=9)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.set_xy(14, row_y + 1)
        pdf.cell(55, 6, label)

        pdf.set_font("Helvetica", size=9)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.set_xy(70, row_y + 1)
        pdf.cell(130, 6, str(value))

    # ── Disclaimer ที่ด้านล่างสุด ──
    pdf.set_font("Helvetica", style='I', size=7.5)
    pdf.set_text_color(150, 150, 150)
    pdf.set_xy(10, 275)
    pdf.multi_cell(190, 4,
        "CONFIDENTIAL: This report contains sensitive security findings. "
        "Distribution is restricted to authorized personnel only. "
        "All findings should be remediated according to your organization's security policy.",
        align='C'
    )


def build_executive_summary(pdf: CosvinteReport, findings: list):
    """
    สร้างหน้า Executive Summary — ส่วนที่ผู้บริหารอ่านก่อน
    ต้องบอกภาพรวมทั้งหมดในหน้าเดียว: จำนวน, ความรุนแรง, ความเสี่ยงหลัก
    """
    pdf.add_page()
    pdf.section_header("Executive Summary", 1)

    # ── ย่อหน้าเปิด ──
    total = len(findings)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low      = sum(1 for f in findings if f["severity"] == "LOW")
    interps  = sum(1 for f in findings if f["is_interpreter"])
    max_score = max((f["risk_score"] for f in findings), default=0)

    # ข้อความสรุปภาพรวม
    summary_text = (
        f"This security assessment identified {total} binaries on the target system "
        f"with potentially dangerous Linux capabilities assigned. "
        f"Of these, {critical} findings are rated CRITICAL, {high} HIGH, "
        f"{medium} MEDIUM, and {low} LOW severity. "
        f"The overall risk score for this system is {max_score:.1f}/10.0, "
        f"indicating a {'CRITICAL' if max_score >= 9 else 'HIGH' if max_score >= 7 else 'MEDIUM'} "
        f"level of exposure. "
        f"Immediate remediation is required for all CRITICAL and HIGH severity findings."
    )

    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
    pdf.set_x(10)
    pdf.multi_cell(190, 6, summary_text)
    pdf.ln(4)

    # ── Stat Cards (4 กล่องแสดงตัวเลข) ──
    # แนวคิด: วาง 4 กล่องเรียงในแถวเดียว แต่ละกล่องกว้าง ~44mm
    card_configs = [
        ("CRITICAL", critical, CosvinteReport.COLOR_CRITICAL),
        ("HIGH",     high,     CosvinteReport.COLOR_HIGH),
        ("MEDIUM",   medium,   CosvinteReport.COLOR_MEDIUM),
        ("LOW",      low,      CosvinteReport.COLOR_LOW),
    ]

    card_y = pdf.get_y()
    card_w = 44
    card_h = 28
    gap    = 2.5

    for i, (label, count, color) in enumerate(card_configs):
        card_x = 10 + i * (card_w + gap)

        # กล่องพื้นหลัง
        pdf.set_fill_color(*color)
        pdf.rect(card_x, card_y, card_w, card_h, style='F')

        # ตัวเลข (ใหญ่)
        pdf.set_font("Helvetica", style='B', size=22)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(card_x, card_y + 3)
        pdf.cell(card_w, 12, str(count), align='C')

        # Label
        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_xy(card_x, card_y + 15)
        pdf.cell(card_w, 8, label, align='C')

        # Subtext "findings"
        pdf.set_font("Helvetica", size=7)
        pdf.set_xy(card_x, card_y + 21)
        pdf.cell(card_w, 6, "findings", align='C')

    pdf.set_xy(10, card_y + card_h + 6)
    pdf.set_text_color(*CosvinteReport.COLOR_TEXT)

    # ── Key Risk Highlights ──
    pdf.set_font("Helvetica", style='B', size=11)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 8, "Key Risk Highlights", align='L')
    pdf.ln(2)

    highlights = []
    if critical > 0:
        highlights.append(
            f"► {critical} CRITICAL capability assignment(s) found — these grant near-root "
            f"privileges and must be removed immediately."
        )
    if interps > 0:
        highlights.append(
            f"► {interps} scripting interpreter(s) (Python, Perl, Node, etc.) have dangerous "
            f"capabilities — these are trivially exploitable with one-liner commands."
        )
    if any(f["world_writable"] for f in findings):
        ww = sum(1 for f in findings if f["world_writable"])
        highlights.append(
            f"► {ww} world-writable binary/binaries with capabilities detected — "
            f"any local user can replace the binary and escalate privileges."
        )
    highlights.append(
        "► All CRITICAL and HIGH findings should be treated as active privilege escalation "
        "vectors until remediated."
    )

    for h in highlights:
        pdf.info_box(h, box_color=(255, 245, 245), text_color=(100, 20, 20))
        pdf.ln(1)

    # ── Risk Score Overview Table ──
    pdf.ln(3)
    pdf.set_font("Helvetica", style='B', size=11)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 8, "Top 5 Highest Risk Binaries", align='L')
    pdf.ln(2)

    # หัวตาราง
    headers = ["Binary", "Capability", "Score", "Severity", "Interpreter?"]
    col_w   = [65, 50, 22, 28, 25]

    pdf.set_fill_color(*CosvinteReport.COLOR_TABLE_HDR)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", style='B', size=8.5)
    for h, w in zip(headers, col_w):
        pdf.cell(w, 8, f"  {h}", border=0, fill=True, align='L')
    pdf.ln()

    # แถวข้อมูล (Top 5)
    pdf.set_font("Helvetica", size=8.5)
    for i, f in enumerate(findings[:5]):
        # สลับสีแถว
        if i % 2 == 0:
            pdf.set_fill_color(*CosvinteReport.COLOR_ROW_ALT)
        else:
            pdf.set_fill_color(255, 255, 255)

        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)

        # ชื่อ binary (ตัดให้สั้นถ้ายาวเกิน)
        bin_name = f["binary"]
        if len(bin_name) > 32:
            bin_name = "..." + bin_name[-29:]

        pdf.cell(col_w[0], 7, f"  {bin_name}", border=0, fill=True)
        pdf.cell(col_w[1], 7, f"  {f['capability']}", border=0, fill=True)

        # Score: ใช้สีตาม severity
        sev_color = CosvinteReport().severity_color(f["severity"])
        pdf.set_text_color(*sev_color)
        pdf.cell(col_w[2], 7, f"  {f['risk_score']:.1f}", border=0, fill=True)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)

        pdf.cell(col_w[3], 7, f"  {f['severity']}", border=0, fill=True)
        interp_txt = "YES ⚠" if f["is_interpreter"] else "No"
        pdf.set_text_color(200, 30, 30) if f["is_interpreter"] else pdf.set_text_color(80, 120, 80)
        pdf.cell(col_w[4], 7, f"  {interp_txt}", border=0, fill=True)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.ln()

    # เส้นล่างตาราง
    pdf.set_draw_color(200, 205, 220)
    pdf.set_line_width(0.2)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())


def build_detailed_findings(pdf: CosvinteReport, findings: list):
    """
    สร้างส่วน Detailed Findings — หัวใจของรายงาน
    แต่ละ Finding จะมี Card แสดงรายละเอียดครบถ้วน:
    Binary path, Capability, Risk Score Bar, Description, Exploit, CVEs, Remediation
    """
    pdf.add_page()
    pdf.section_header("Detailed Findings", 2)

    pdf.set_font("Helvetica", size=9)
    pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
    pdf.multi_cell(190, 5,
        "Each finding below represents a Linux capability assigned to a binary that poses "
        "a security risk. Findings are sorted by risk score (highest first). "
        "The exploit notes are provided for educational purposes to demonstrate impact."
    )
    pdf.ln(3)

    for idx, f in enumerate(findings):
        # ── ตรวจว่าหน้าเต็มหรือยัง (เผื่อที่สำหรับ Card ~80mm) ──
        if pdf.get_y() > 220:
            pdf.add_page()

        card_start_y = pdf.get_y()
        sev_color    = pdf.severity_color(f["severity"])

        # ┌── Finding Card: เส้นขอบซ้าย ──────────────────────────┐
        # วาดเส้นขอบซ้ายสีตาม severity (เส้นหนา)
        pdf.set_fill_color(*sev_color)
        # จะกำหนดความสูง Card หลังจากวาด content แล้ว

        # ── Finding Header ──
        # กล่องหัว Finding
        pdf.set_fill_color(30, 35, 60)
        pdf.rect(10, card_start_y, 190, 10, style='F')

        pdf.set_font("Helvetica", style='B', size=9)
        pdf.set_text_color(*CosvinteReport.COLOR_ACCENT)
        pdf.set_xy(14, card_start_y + 1.5)
        pdf.cell(10, 7, f"#{idx+1:02d}", align='L')

        # ชื่อ Binary
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(25, card_start_y + 1.5)
        pdf.cell(100, 7, f["binary"], align='L')

        # Severity Badge ด้านขวา
        pdf.set_fill_color(*sev_color)
        pdf.rect(165, card_start_y + 1.5, 33, 7, style='F')
        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(165, card_start_y + 2)
        pdf.cell(33, 6, f["severity"], align='C')

        pdf.set_xy(10, card_start_y + 12)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)

        # ── Row 1: Capability + Type + Owner ──
        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(30, 5, "Capability:")
        pdf.set_font("Helvetica", size=8)
        pdf.set_text_color(80, 50, 150)  # สีม่วงสำหรับ cap name
        pdf.cell(50, 5, f["capability"])

        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(20, 5, "Type:")
        pdf.set_font("Helvetica", size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(40, 5, f["cap_type"])

        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(15, 5, "Owner:")
        pdf.set_font("Helvetica", size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(30, 5, f["owner"])
        pdf.ln(6)

        # ── Row 2: Risk Score Bar ──
        pdf.set_x(10)
        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(30, 5, "Risk Score:")
        pdf.draw_cvss_bar(pdf.get_x(), pdf.get_y() + 0.5, f["risk_score"], bar_w=80)
        pdf.ln(7)

        # ── Row 3: Description ──
        pdf.set_x(10)
        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(30, 5, "Description:")
        pdf.set_font("Helvetica", size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.set_x(40)
        pdf.multi_cell(160, 4.5, f["description"])
        pdf.ln(1)

        # ── Row 4: Exploit Hint (กล่องสีแดงอ่อน) ──
        if f["exploit_hint"]:
            pdf.set_x(10)
            pdf.set_fill_color(255, 240, 240)
            box_y = pdf.get_y()
            pdf.rect(10, box_y, 190, 12, style='F')
            pdf.set_fill_color(200, 30, 30)
            pdf.rect(10, box_y, 1.5, 12, style='F')  # ขอบซ้ายสีแดง

            pdf.set_font("Helvetica", style='B', size=8)
            pdf.set_text_color(180, 0, 0)
            pdf.set_xy(14, box_y + 2)
            pdf.cell(30, 4, "Exploit Vector:")
            pdf.set_font("Courier", size=7.5)  # Monospace สำหรับ code
            pdf.set_text_color(100, 0, 0)
            pdf.set_xy(14, box_y + 6.5)
            # ตัด exploit hint ถ้ายาวเกิน
            exploit_text = f["exploit_hint"]
            if len(exploit_text) > 95:
                exploit_text = exploit_text[:92] + "..."
            pdf.cell(184, 4, exploit_text)
            pdf.set_xy(10, box_y + 13)
            pdf.ln(1)

        # ── Row 5: CVEs ──
        if f["cves"]:
            pdf.set_x(10)
            pdf.set_font("Helvetica", style='B', size=8)
            pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
            pdf.cell(30, 5, "Related CVEs:")
            pdf.set_font("Helvetica", size=8)
            # วาด Badge สำหรับแต่ละ CVE
            for cve in f["cves"][:4]:  # แสดงสูงสุด 4 CVE
                pdf.set_fill_color(220, 235, 255)
                cve_x = pdf.get_x()
                cve_y = pdf.get_y()
                cve_w = len(cve) * 2.2 + 4
                pdf.rect(cve_x, cve_y, cve_w, 5, style='F')
                pdf.set_text_color(0, 60, 150)
                pdf.cell(cve_w, 5, cve, align='C')
                pdf.set_x(pdf.get_x() + 2)  # gap ระหว่าง CVE badge
            pdf.ln(7)

        # ── Row 6: Risk Factors ──
        if f["risk_factors"]:
            pdf.set_x(10)
            pdf.set_font("Helvetica", style='B', size=8)
            pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
            pdf.cell(30, 5, "Risk Factors:")
            pdf.set_font("Helvetica", size=8)
            pdf.set_text_color(160, 100, 0)
            factors_text = " | ".join(f["risk_factors"][:3])
            pdf.set_x(40)
            pdf.multi_cell(160, 4.5, factors_text)

        # ── Row 7: Remediation (กล่องสีเขียวอ่อน) ──
        pdf.set_x(10)
        pdf.set_fill_color(240, 255, 245)
        box_y2 = pdf.get_y()
        rem_text = f["remediation"]
        lines_needed = max(1, len(rem_text) // 90 + 1)
        rem_h = lines_needed * 4.5 + 8
        pdf.rect(10, box_y2, 190, rem_h, style='F')
        pdf.set_fill_color(50, 160, 80)
        pdf.rect(10, box_y2, 1.5, rem_h, style='F')  # ขอบซ้ายสีเขียว

        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_text_color(30, 120, 50)
        pdf.set_xy(14, box_y2 + 2)
        pdf.cell(30, 4, "Remediation:")
        pdf.set_font("Helvetica", size=8)
        pdf.set_text_color(20, 80, 35)
        pdf.set_xy(14, box_y2 + 7)
        pdf.multi_cell(184, 4.5, rem_text)

        # เส้นแบ่งระหว่าง Finding Cards
        pdf.ln(4)
        pdf.set_draw_color(200, 210, 230)
        pdf.set_line_width(0.2)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)


def build_remediation_checklist(pdf: CosvinteReport, findings: list):
    """
    สร้าง Remediation Checklist — ส่วนสุดท้ายที่ใช้ติดตามการแก้ไข
    เหมือน To-Do List สำหรับทีม Security/Sysadmin
    """
    pdf.add_page()
    pdf.section_header("Remediation Checklist", 3)

    pdf.set_font("Helvetica", size=9)
    pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
    pdf.multi_cell(190, 5,
        "Use this checklist to track remediation progress. Items are ordered by severity. "
        "Each item should be verified after remediation using: getcap -r / 2>/dev/null"
    )
    pdf.ln(4)

    # ── General Best Practices Box ──
    pdf.set_font("Helvetica", style='B', size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 7, "General Best Practices", align='L')
    pdf.ln(1)

    best_practices = [
        "Audit all capabilities regularly: getcap -r / 2>/dev/null",
        "Apply Principle of Least Privilege — assign only the minimum capability required",
        "Never assign capabilities to scripting interpreters (Python, Perl, Node, etc.)",
        "Use seccomp profiles and AppArmor/SELinux to constrain capability usage",
        "Monitor capability changes with auditd: auditctl -a always,exit -F arch=b64 -S capset",
        "Remove capabilities instead of relying on file permissions alone",
        "Document all legitimate capability assignments with business justification",
    ]

    for bp in best_practices:
        pdf.set_x(10)
        # วาดกล่อง checkbox
        pdf.set_fill_color(240, 244, 255)
        pdf.rect(10, pdf.get_y(), 190, 7, style='F')
        pdf.set_draw_color(180, 190, 220)
        pdf.set_line_width(0.2)
        # Checkbox square
        pdf.rect(14, pdf.get_y() + 1.5, 4, 4)

        pdf.set_font("Helvetica", size=8.5)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.set_xy(21, pdf.get_y() + 1)
        pdf.cell(177, 5, bp)
        pdf.ln(7.5)

    pdf.ln(4)

    # ── Per-Finding Checklist ──
    pdf.set_font("Helvetica", style='B', size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 7, "Finding-Specific Remediation Tasks", align='L')
    pdf.ln(3)

    # หัวตาราง Checklist
    chk_headers = ["✓", "#", "Binary", "Capability", "Action Required", "Severity"]
    chk_widths  = [8, 8, 55, 32, 67, 20]

    pdf.set_fill_color(*CosvinteReport.COLOR_TABLE_HDR)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", style='B', size=8)
    for h, w in zip(chk_headers, chk_widths):
        pdf.cell(w, 8, f" {h}", border=0, fill=True)
    pdf.ln()

    # แถวข้อมูลแต่ละ Finding
    for i, f in enumerate(findings):
        if pdf.get_y() > 255:
            pdf.add_page()

        # สลับสีแถว
        if i % 2 == 0:
            pdf.set_fill_color(*CosvinteReport.COLOR_ROW_ALT)
        else:
            pdf.set_fill_color(255, 255, 255)

        row_y = pdf.get_y()

        # Checkbox
        pdf.set_fill_color(*( (255,245,245) if i%2==0 else (255,255,255) ))
        pdf.cell(chk_widths[0], 7, "", border=0, fill=True)
        # วาด checkbox
        pdf.set_draw_color(150, 160, 180)
        pdf.rect(11, row_y + 1.5, 4.5, 4.5)

        # หมายเลข
        pdf.set_font("Helvetica", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(chk_widths[1], 7, f" {i+1:02d}", border=0, fill=True)

        # Binary name (ตัดสั้น)
        bin_short = os.path.basename(f["binary"])
        pdf.set_font("Helvetica", size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(chk_widths[2], 7, f" {bin_short[:28]}", border=0, fill=True)

        # Capability
        pdf.set_text_color(80, 50, 150)
        pdf.cell(chk_widths[3], 7, f" {f['capability']}", border=0, fill=True)

        # Action: ดึงมาจาก remediation (ตัดสั้น)
        action = f["remediation"].split(".")[0]  # เอาแค่ประโยคแรก
        if len(action) > 38:
            action = action[:35] + "..."
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(chk_widths[4], 7, f" {action}", border=0, fill=True)

        # Severity badge color ในตาราง
        sev_color = pdf.severity_color(f["severity"])
        pdf.set_text_color(*sev_color)
        pdf.set_font("Helvetica", style='B', size=7.5)
        pdf.cell(chk_widths[5], 7, f" {f['severity']}", border=0, fill=True)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.ln()

    # ── Verification Commands ──
    pdf.ln(6)
    if pdf.get_y() > 220:
        pdf.add_page()

    pdf.set_font("Helvetica", style='B', size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 7, "Verification Commands", align='L')
    pdf.ln(2)

    verify_cmds = [
        ("List all capabilities on system",
         "getcap -r / 2>/dev/null"),
        ("Remove capability from binary",
         "setcap -r /path/to/binary"),
        ("Verify capability removed",
         "getcap /path/to/binary  # should return empty"),
