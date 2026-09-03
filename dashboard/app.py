"""Flask application for the local Westbridge analyst dashboard."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, url_for

from dashboard.audit import record
from dashboard.auth import load_role, require
from dashboard.database import detections, incident_detail, incident_list, overview, search
from incidents.database import add_note
from metrics.attack_coverage import attack_coverage
from response.actions import approve_action, create_action, simulate_action

ROOT = Path(__file__).resolve().parents[1]


def create_app(database: Path | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(DATABASE=str(database or ROOT / "data/events.db"),
                      RULES=str(ROOT / "detection_engine/rules"),
                      GROUND_TRUTH=str(ROOT / "data/metadata/detection_ground_truth.json"))

    @app.before_request
    def prepare():
        load_role()
        g.db = sqlite3.connect(app.config["DATABASE"])

    @app.teardown_request
    def close(_error):
        if getattr(g, "db", None): g.db.close()

    @app.context_processor
    def context(): return {"role": g.role}

    @app.get("/")
    @require("view")
    def index():
        return render_template("overview.html", data=overview(g.db, Path(app.config["RULES"]), Path(app.config["GROUND_TRUTH"])))

    @app.get("/detections")
    @require("view")
    def detection_page(): return render_template("detections.html", data=detections(g.db, Path(app.config["GROUND_TRUTH"])))

    @app.get("/incidents")
    @require("view")
    def incidents_page():
        keys = ("severity", "status", "host", "user", "tactic", "technique", "detection", "from", "to")
        filters = {key: request.args.get(key, "") for key in keys}
        return render_template("incidents.html", incidents=incident_list(g.db, filters), filters=filters)

    @app.get("/incidents/<incident_id>")
    @require("view")
    def incident_page(incident_id):
        data = incident_detail(g.db, incident_id)
        if data is None: abort(404)
        record(g.db, request.headers.get("X-Lab-Analyst", "local-user"), g.role, "VIEW_INCIDENT", "incident", incident_id)
        return render_template("incident.html", data=data)

    @app.get("/evidence/<int:event_id>")
    @require("view")
    def evidence_page(event_id):
        row = g.db.execute("SELECT raw_xml FROM events WHERE id=?", (event_id,)).fetchone()
        if row is None: abort(404)
        record(g.db, request.headers.get("X-Lab-Analyst", "local-user"), g.role, "VIEW_EVIDENCE", "event", str(event_id))
        return app.response_class(row[0], mimetype="application/xml")

    @app.post("/incidents/<incident_id>/notes")
    @require("add_note")
    def note(incident_id):
        analyst = request.headers.get("X-Lab-Analyst", "local-analyst")
        add_note(g.db, incident_id, analyst, request.form.get("body", ""))
        record(g.db, analyst, g.role, "ADD_NOTE", "incident", incident_id)
        return redirect(url_for("incident_page", incident_id=incident_id, role=g.role))

    @app.post("/incidents/<incident_id>/response")
    @require("respond")
    def response_plan(incident_id):
        analyst = request.headers.get("X-Lab-Analyst", "local-responder")
        action, _ = create_action(g.db, incident_id, request.form.get("action_type", ""),
                                  request.form.get("target", ""), request.form.get("rationale", ""), analyst,
                                  request.form.getlist("evidence_alert"))
        record(g.db, analyst, g.role, "CREATE_RESPONSE_ACTION", "response_action", action.action_id)
        return redirect(url_for("incident_page", incident_id=incident_id, role=g.role))

    @app.post("/response/<action_id>/<operation>")
    @require("respond")
    def response_transition(action_id, operation):
        analyst = request.headers.get("X-Lab-Analyst", "local-responder")
        if operation == "approve": approve_action(g.db, action_id); audit_action = "APPROVE_RESPONSE"
        elif operation == "simulate": simulate_action(g.db, action_id); audit_action = "SIMULATE_RESPONSE"
        else: abort(404)
        action = g.db.execute("SELECT i.incident_id FROM response_actions r JOIN incidents i ON i.id=r.incident_id WHERE r.action_id=?", (action_id,)).fetchone()
        record(g.db, analyst, g.role, audit_action, "response_action", action_id)
        return redirect(url_for("incident_page", incident_id=action[0], role=g.role))

    @app.get("/attack")
    @require("view")
    def attack_page(): return render_template("attack.html", data=attack_coverage(g.db, Path(app.config["RULES"]), Path(app.config["GROUND_TRUTH"])))

    @app.get("/search")
    @require("view")
    def search_page(): return render_template("search.html", term=request.args.get("q", ""), results=search(g.db, request.args.get("q", "")))

    return app


def main() -> None:
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)


if __name__ == "__main__": main()
