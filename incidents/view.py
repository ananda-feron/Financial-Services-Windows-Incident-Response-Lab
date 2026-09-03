"""Render a focused, static incident investigation page from referenced evidence."""

from __future__ import annotations

import html
import sqlite3
from pathlib import Path

from incidents.database import evidence_xml, notes, timeline


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def render_incident_page(connection: sqlite3.Connection, incident_id: str, output: Path) -> None:
    row = connection.execute("""SELECT title, severity, status, description, hostname,
      username, first_seen, last_seen FROM incidents WHERE incident_id = ?""", (incident_id,)).fetchone()
    if row is None:
        raise ValueError(f"unknown incident: {incident_id}")
    entries = timeline(connection, incident_id)
    analyst_notes = notes(connection, incident_id)
    techniques = sorted({(entry.technique_id, entry.technique_name) for entry in entries})
    timeline_html = []
    for entry in entries:
        raw = evidence_xml(connection, incident_id, entry.event_id) or "Evidence unavailable"
        timeline_html.append(f"""<article class="event">
          <time>{esc(entry.timestamp)}</time><h3>{esc(entry.technique_name)}</h3>
          <p><span>{esc(entry.alert_id)}</span> · {esc(entry.detection_id)} · {esc(entry.severity.upper())} · Windows Event {entry.windows_event_id}</p>
          <p>{esc(entry.hostname)} · {esc(entry.username or 'Unresolved user')} · {esc(entry.source_file)}</p>
          <details id="event-{entry.event_id}"><summary>View referenced original event XML</summary><pre>{esc(raw)}</pre></details>
        </article>""")
    notes_html = "".join(f"<blockquote><p>{esc(note.body)}</p><footer>{esc(note.author)} · {esc(note.created_at)}</footer></blockquote>" for note in analyst_notes) or "<p>No analyst notes recorded.</p>"
    technique_html = "".join(f"<li><strong>{esc(tid)}</strong> {esc(name)}</li>" for tid, name in techniques)
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{esc(incident_id)} — Investigation</title><style>
    :root{{--bg:#071426;--panel:#10253e;--text:#ecf5ff;--muted:#acc2d9;--accent:#63d1ff;--critical:#ff7070}}
    *{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px system-ui,sans-serif;line-height:1.55}}
    main{{max-width:1060px;margin:auto;padding:48px 24px}}header,.panel{{background:var(--panel);border:1px solid #294968;border-radius:16px;padding:24px;margin-bottom:20px}}
    h1{{margin:.15em 0}}h2{{color:var(--accent)}}.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}}
    .meta div{{background:#173451;border-radius:10px;padding:12px}}.meta small,time,footer{{color:var(--muted)}}ul{{padding-left:20px}}
    .event{{border-left:3px solid var(--accent);padding:0 0 28px 22px;margin-left:8px}}.event h3{{margin:.25em 0}}.event p{{color:var(--muted)}}
    span{{color:var(--accent)}}summary{{cursor:pointer;color:var(--accent)}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#06101d;padding:16px;border-radius:8px;max-height:320px;overflow:auto}}
    blockquote{{border-left:3px solid #9d8cff;margin-left:0;padding-left:18px}}a{{color:var(--accent)}}
    </style></head><body><main><header><small>WESTBRIDGE FINANCIAL · SYNTHETIC LAB</small><h1>{esc(incident_id)} — {esc(row[0])}</h1><p>{esc(row[3])}</p>
    <section class="meta"><div><small>STATUS</small><br><strong>{esc(row[2])}</strong></div><div><small>SEVERITY</small><br><strong>{esc(row[1].upper())}</strong></div><div><small>HOST</small><br><strong>{esc(row[4])}</strong></div><div><small>USER</small><br><strong>{esc(row[5] or 'Unresolved')}</strong></div><div><small>FIRST SEEN</small><br>{esc(row[6])}</div><div><small>LAST SEEN</small><br>{esc(row[7])}</div></section></header>
    <section class="panel"><h2>ATT&amp;CK context</h2><ul>{technique_html}</ul></section>
    <section class="panel"><h2>Investigation timeline</h2>{''.join(timeline_html)}</section>
    <section class="panel"><h2>Analyst notes</h2>{notes_html}</section>
    <p><small>Generated from SQLite references. Expanding evidence reads the preserved event XML associated with the incident; the incident record does not duplicate it.</small></p>
    </main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
