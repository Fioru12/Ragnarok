"""
Asgard RAG — Command Line Interface.

Permette di indicizzare, ricercare e ottenere insight RAG senza avviare il server.

Uso:
  python -m rag.cli index
  python -m rag.cli query "quali IP sono stati bloccati?"
  python -m rag.cli insights
  python -m rag.cli stats
"""
import argparse
import sys
import os
from datetime import datetime


def _make_indexer():
    from rag.indexer import AsgardIndexer
    root = os.environ.get("ASGARD_ROOT")
    return AsgardIndexer(asgard_root=root) if root else AsgardIndexer()


def _make_retriever():
    from rag.retriever import AsgardRetriever
    return AsgardRetriever()


def cmd_index(args):
    idx = _make_indexer()
    results = idx.index_all()
    print("\n[ASGARD] Indicizzazione completata:")
    for k, v in results.items():
        print(f"  {k}: {v}")


def cmd_query(args):
    retriever = _make_retriever()
    results = retriever.search(args.query, n_results=args.n, sources=args.sources)
    if not results:
        print("Nessun risultato trovato. Prova 'index' prima.")
        return
    print(f"\n[ASGARD] {len(results)} risultati per: {args.query}\n")
    for i, r in enumerate(results, 1):
        meta = r.get("metadata", {})
        print(f"[{i}] {meta.get('source', '?')} | {meta.get('type', '?')} | sim {r['similarity']:.0%}")
        print(f"    {r['text'][:200]}")
        print()


def _print_utf8(text):
    """Stampa sicura su console Windows (cp1252 non supporta le emoji)."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    print(text)


def cmd_insights(args):
    from rag.insights import InsightsEngine
    engine = InsightsEngine()
    _print_utf8(engine.format_for_llm())


def cmd_report(args):
    from rag.insights import InsightsEngine
    from rag.report import ReportExporter
    engine = InsightsEngine()
    exporter = ReportExporter(engine=engine)
    if args.pdf:
        try:
            from rag.pdf_report import PDFReportExporter
            pdf_exporter = PDFReportExporter(report_exporter=exporter)
            path = pdf_exporter.save(output_dir=args.out or None)
            print(f"[ASGARD] PDF salvato: {path}")
        except ImportError:
            print("[ASGARD] Errore: fpdf2 non installato. Esegui: pip install fpdf2")
    elif args.save:
        path = exporter.save(output_dir=args.out)
        print(f"[ASGARD] Report salvato: {path}")
    else:
        _print_utf8(exporter.generate_markdown())


def cmd_stats(args):
    idx = _make_indexer()
    stats = idx.get_stats()
    total = sum(stats.values())
    print(f"\n[ASGARD] Documenti indicizzati: {total}")
    for name, count in stats.items():
        print(f"  {name}: {count}")


def cmd_notify(args):
    from rag.insights import InsightsEngine
    from rag import dispatch
    engine = InsightsEngine()
    if args.save:
        result = dispatch.export_and_notify(output_dir=args.out, engine=engine)
        print(f"[ASGARD] Report salvato: {result.get('report_path')}")
    else:
        result = dispatch.send_report(engine=engine)
    if not result.get("configured"):
        print("[ASGARD] Gjallarhorn non configurato (GJALLARHORN_HUB_URL / GJALLARHORN_API_KEY): nessun invio.")
        return
    status = "inviato" if result.get("sent") else "NON inviato (hub irraggiungibile?)"
    print(f"[ASGARD] Notifica {status} | severità: {result.get('severity')}")
    _print_utf8(result.get("message", ""))


def cmd_anomalies(args):
    from rag import dispatch
    result = dispatch.send_timeline_alert(days=args.days)
    if not result.get("configured"):
        print("[ASGARD] Gjallarhorn non configurato (GJALLARHORN_HUB_URL / GJALLARHORN_API_KEY): nessun invio.")
        return
    if result.get("anomalies", 0) == 0:
        print("[ASGARD] Nessuna anomalia rilevata: nessun alert inviato.")
        return
    status = "inviato" if result.get("sent") else "NON inviato (hub irraggiungibile?)"
    print(f"[ASGARD] Alert anomalie {status} | severità: {result.get('severity')} | spike: {result.get('anomalies')}")
    _print_utf8(result.get("message", ""))


def cmd_security(args):
    """Security audit della configurazione RAG."""
    from rag.security import SecurityAuditor
    auditor = SecurityAuditor()
    report = auditor.run_audit()
    if args.save:
        path = auditor.save_report(output_dir=args.out)
        print(f"[ASGARD] Report sicurezza salvato: {path}")
    else:
        _print_utf8(report)


def cmd_gdpr(args):
    """GDPR: checklist, raccomandazione agenti o report privacy."""
    from rag.gdpr import GDPRComplianceChecker, GDPR_CHECKLIST
    checker = GDPRComplianceChecker()
    if args.action == "checklist":
        _print_utf8("\n=== CHECKLIST GDPR ===")
        for item in GDPR_CHECKLIST:
            _print_utf8(f"  [{item['principio']}] {item['question']} (peso {item['peso']})")
    elif args.action == "recommend":
        rec = checker.recommend_agents(args.size, args.sector, args.maturity)
        _print_utf8("\n=== RACCOMANDAZIONE AGENTI ===")
        _print_utf8(f"Azienda: {rec['company_size']} (settore: {rec['sector']}, maturità: {rec['maturity']})")
        _print_utf8(f"Consigliati: {', '.join(rec['recommended_agents'])}")
        if rec['optional_agents']:
            _print_utf8(f"Opzionali: {', '.join(rec['optional_agents'])}")
        _print_utf8(f"Motivazione: {rec['reasoning']}")
    elif args.action == "report":
        report = checker.generate_privacy_report(company_size=args.size)
        _print_utf8("\n=== REPORT GDPR ===")
        _print_utf8(f"Score: {report['gdpr_evaluation']['percentage']}% ({report['gdpr_evaluation']['level']})")
        _print_utf8(f"Agenti consigliati: {', '.join(report['agent_recommendations']['recommended_agents'])}")
        _print_utf8(f"\n{report['disclaimer']}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="rag", description="Asgard RAG CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_index = sub.add_parser("index", help="Indicizza i dati dei moduli Asgard")
    p_index.set_defaults(func=cmd_index)

    p_query = sub.add_parser("query", help="Ricerca semantica")
    p_query.add_argument("query", help="Domanda in linguaggio naturale")
    p_query.add_argument("-n", "--n", type=int, default=5, help="Numero risultati")
    p_query.add_argument("--sources", nargs="*", help="Filtra per fonte (heimdall, fenrir, ecc.)")
    p_query.set_defaults(func=cmd_query)

    p_insight = sub.add_parser("insights", help="Analisi proattiva dei dati")
    p_insight.set_defaults(func=cmd_insights)

    p_report = sub.add_parser("report", help="Report Markdown proattivo")
    p_report.add_argument("--save", action="store_true", help="Salva su file invece di stampare")
    p_report.add_argument("--pdf", action="store_true", help="Genera PDF formale per il management")
    p_report.add_argument("--out", default=None, help="Directory di destinazione (default: output/reports)")
    p_report.set_defaults(func=cmd_report)

    p_notify = sub.add_parser("notify", help="Invia il digest del report via Gjallarhorn")
    p_notify.add_argument("--save", action="store_true", help="Salva anche il report Markdown completo")
    p_notify.add_argument("--out", default=None, help="Directory del report se --save")
    p_notify.set_defaults(func=cmd_notify)

    p_anom = sub.add_parser("anomalies", help="Rileva spike anomali e invia alert via Gjallarhorn")
    p_anom.add_argument("--days", type=int, default=30, help="Finestra di analisi (default: 30)")
    p_anom.set_defaults(func=cmd_anomalies)

    p_security = sub.add_parser("security", help="Security audit della configurazione")
    p_security.add_argument("--save", action="store_true", help="Salva il report su file")
    p_security.add_argument("--out", default=None, help="Directory di destinazione")
    p_security.set_defaults(func=cmd_security)

    p_gdpr = sub.add_parser("gdpr", help="GDPR: checklist, raccomandazione agenti, report")
    p_gdpr.add_argument("action", choices=["checklist", "recommend", "report"],
                        help="Azione GDPR")
    p_gdpr.add_argument("--size", default="small", choices=["micro", "small", "medium", "enterprise"],
                        help="Dimensione azienda (default: small)")
    p_gdpr.add_argument("--sector", default=None, help="Settore (sanita, finanza, assicurazioni, ecc.)")
    p_gdpr.add_argument("--maturity", default=None, choices=["base", "avanzata"],
                        help="Maturità nella gestione dati personali")
    p_gdpr.set_defaults(func=cmd_gdpr)

    p_sec_hist = sub.add_parser("security-history", help="Storico security score nel tempo")
    p_sec_hist.add_argument("--days", type=int, default=30, help="Periodo di analisi (default: 30)")
    p_sec_hist.add_argument("--record", action="store_true", help="Salva il punteggio corrente")
    p_sec_hist.set_defaults(func=cmd_security_history)

    p_stats = sub.add_parser("stats", help="Statistiche indice")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()