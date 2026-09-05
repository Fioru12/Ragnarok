import sys, os, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import traceback
try:
    from rag.pdf_report import PDFReportExporter
    from rag.report import ReportExporter
    e = PDFReportExporter(report_exporter=ReportExporter())
    path = e.generate_pdf()
    print("OK:", path)
except Exception:
    traceback.print_exc()