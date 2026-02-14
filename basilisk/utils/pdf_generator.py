"""
Basilisk PDF Report Generator
Automated security audit report generation with color-coded severity levels.
"""
from fpdf import FPDF
from datetime import datetime
from typing import List, Tuple, Any


class PDFReport(FPDF):
    """Custom PDF template with standardized header and footer."""

    def header(self) -> None:
        self.set_font('Arial', 'B', 15)
        self.cell(80)
        self.cell(30, 10, 'basilisk - Security Audit Report', 0, 0, 'C')
        self.ln(20)
        self.set_line_width(0.5)
        self.line(10, 25, 200, 25)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')


def generate_pdf(
    events: List[Tuple[Any, ...]],
    filename: str = "security_report.pdf"
) -> Tuple[bool, str]:
    """
    Generate formatted PDF report from security events.
    
    Args:
        events: List of (timestamp, type, severity, message) tuples
        filename: Output file path
        
    Returns:
        Tuple[bool, str]: (success_status, output_path_or_error)
    """
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(200, 10, f"Total Incidents: {len(events)}", ln=True)
    pdf.ln(10)

    pdf.set_fill_color(52, 152, 219)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(40, 10, "Date", 1, 0, 'C', True)
    pdf.cell(25, 10, "Type", 1, 0, 'C', True)
    pdf.cell(25, 10, "Level", 1, 0, 'C', True)
    pdf.cell(100, 10, "Details", 1, 1, 'C', True)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", size=9)

    for event in events:
        ts, type_, severity, msg = event

        if severity == "CRITICAL":
            pdf.set_text_color(192, 57, 43)
        else:
            pdf.set_text_color(0, 0, 0)

        clean_msg = str(msg).replace('\n', ' ')[:60]

        pdf.cell(40, 10, str(ts), 1)
        pdf.cell(25, 10, str(type_), 1)
        pdf.cell(25, 10, str(severity), 1)
        pdf.cell(100, 10, clean_msg, 1, 1)

    try:
        pdf.output(filename)
        return True, filename
    except Exception as e:
        return False, str(e)