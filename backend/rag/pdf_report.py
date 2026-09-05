"""
Asgard RAG — PDF Report Exporter.

Converte il report proattivo in PDF formale per il management.
Usa fpdf2 (pura Python, zero dipendenze di sistema).
"""
import os
import logging
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger("Asgard.RAG.PDFReport")


class PDFReportExporter:
    """Genera PDF dal report proattivo."""

    def __init__(self, engine=None, engine_kwargs=None, report_exporter=None):
        from rag.insights import InsightsEngine
        from rag.report import ReportExporter
        if report_exporter is not None:
            self.engine = report_exporter.engine
        else:
            self.engine = engine if engine is not None else InsightsEngine(**(engine_kwargs or {}))

    @staticmethod
    def _clean(text: str) -> str:
        """Rimuove caratteri Unicode non supportati da font base."""
        text = text.replace("\u2014", "-").replace("\u2013", "-")
        text = text.replace("\u2018", "'").replace("\u2019", "'")
        text = text.replace("\u201c", '"').replace("\u201d", '"')
        text = text.replace("\u2022", "-")
        return text

    @staticmethod
    def _clean_markdown(text: str) -> str:
        """Rimuove formatting Markdown (bold, italic, code, link)."""
        text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)  # **bold**
        text = re.sub(r'\*(.+?)\*', r'\1', text)      # *italic*
        text = re.sub(r'`(.+?)`', r'\1', text)        # `code`
        text = re.sub(r'\[(.+?)\]\(.+?\)', r'\1', text)  # [link](url)
        return text

    @staticmethod
    def _parse_md_to_structured(md: str):
        """Parser Markdown semplice: separa header, tabelle, liste e testo."""
        elements = []
        for line in md.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('#'):
                elements.append({'type': 'header', 'text': stripped.lstrip('#').strip()})
            elif stripped.startswith('|') and stripped.endswith('|'):
                elements.append({'type': 'table', 'text': stripped})
            elif stripped.startswith('- ') or stripped.startswith('* '):
                elements.append({'type': 'list', 'text': stripped[2:]})
            else:
                elements.append({'type': 'text', 'text': stripped})
        return elements

    def generate_pdf(self, output_path: Optional[str] = None) -> bytes:
        """Genera il PDF e restituisce i byte (e salva se output_path e' dato)."""
        from rag.report import ReportExporter
        from fpdf import FPDF

        summary = self.engine.summary()
        report = ReportExporter(engine=self.engine)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Helvetica", "", 11)

        # Titolo
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, self._clean("Asgard - Report Proattivo di Sicurezza"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 6, self._clean(f"Generato il {summary.get('generated_at', datetime.now().isoformat())}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

        # Top IP
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, self._clean("Top IP Attaccanti"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for e in summary.get("top_ips", []):
            pdf.cell(0, 6, self._clean(f"- {e.get('ip', '')}: {e.get('count', '')} alert (max: {e.get('max_severity', '')})"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Severita
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, self._clean("Distribuzione Severita"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for k, v in sorted(summary.get("severity_distribution", {}).items()):
            pdf.cell(0, 6, self._clean(f"- {k}: {v}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # IOC
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, self._clean("IOC Ricorrenti"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for e in summary.get("top_ioc", []):
            pdf.cell(0, 6, self._clean(f"- {e.get('value', '')} (x{e.get('count', '')})"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # CVE
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, self._clean("CVE Correlate"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for e in summary.get("cve_references", []):
            pdf.cell(0, 6, self._clean(f"- {e.get('cve', '')} (x{e.get('count', '')})"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Compliance
        comp = summary.get("compliance", {})
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, "Compliance", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, self._clean(f"Report Forseti indicizzati: {comp.get('assessment_files', 0)}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Playbook
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, self._clean("Playbook Sleipnir Disponibili"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for e in summary.get("playbooks", []):
            pdf.cell(0, 6, self._clean(f"- {e.get('playbook', '')}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Raccomandazioni
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 9, self._clean("Raccomandazioni"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for rec in report.build_recommendations(summary):
            for line in self._clean(rec).split(". "):
                if line.strip():
                    pdf.cell(0, 6, f"- {line.strip()}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        # Footer
        pdf.set_y(-18)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 6, self._clean("Report generato automaticamente dal RAG Engine di Ragnarok."), new_x="LMARGIN", new_y="NEXT", align="C")

        data = bytes(pdf.output())

        # Contratto: con output_path (o ASGARD_REPORT_DIR) -> salva e ritorna il path;
        # altrimenti ritorna i bytes.
        if output_path is None:
            report_dir = os.environ.get("ASGARD_REPORT_DIR")
            if report_dir:
                output_path = self._default_output_path(report_dir)
        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(data)
            logger.info(f"PDF salvato: {output_path}")
            return output_path
        return data

    @staticmethod
    def _default_output_path(report_dir: str) -> str:
        os.makedirs(report_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return os.path.join(report_dir, f"asgard_report_{ts}.pdf")

    def save(self, output_dir: Optional[str] = None) -> str:
        if output_dir is None:
            output_dir = os.environ.get(
                "ASGARD_REPORT_DIR",
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "output", "reports"),
            )
        path = self._default_output_path(output_dir)
        return self.generate_pdf(output_path=path)