# pysentinel/utils/pdf_generator.py
from fpdf import FPDF
from datetime import datetime

class PDFReport(FPDF):
    def header(self):
        # Logo o Título
        self.set_font('Arial', 'B', 15)
        self.cell(80)
        self.cell(30, 10, 'PySentinel - Informe de Seguridad', 0, 0, 'C')
        self.ln(20)
        
        # Línea divisoria
        self.set_line_width(0.5)
        self.line(10, 25, 200, 25)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')

def generate_pdf(events, filename="reporte_seguridad.pdf"):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    # Info General
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, f"Fecha del Reporte: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(200, 10, f"Total Incidentes: {len(events)}", ln=True)
    pdf.ln(10)

    # Tabla de Eventos
    # Encabezados
    pdf.set_fill_color(52, 152, 219) # Azul bonito
    pdf.set_text_color(255, 255, 255) # Blanco
    pdf.cell(40, 10, "Fecha", 1, 0, 'C', True)
    pdf.cell(25, 10, "Tipo", 1, 0, 'C', True)
    pdf.cell(25, 10, "Nivel", 1, 0, 'C', True)
    pdf.cell(100, 10, "Detalle", 1, 1, 'C', True)

    # Datos
    pdf.set_text_color(0, 0, 0) # Negro
    pdf.set_font("Arial", size=9)
    
    for event in events:
        # event es (timestamp, type, severity, message)
        ts, tipo, sev, msg = event
        
        # Colorear texto si es crítico
        if sev == "CRITICAL":
            pdf.set_text_color(192, 57, 43) # Rojo
        else:
            pdf.set_text_color(0, 0, 0)

        # Limpiar mensaje largo
        clean_msg = msg.replace('\n', ' ')[:60]

        pdf.cell(40, 10, str(ts), 1)
        pdf.cell(25, 10, str(tipo), 1)
        pdf.cell(25, 10, str(sev), 1)
        pdf.cell(100, 10, clean_msg, 1, 1) # El último 1 es salto de línea

    try:
        pdf.output(filename)
        return True, filename
    except Exception as e:
        return False, str(e)