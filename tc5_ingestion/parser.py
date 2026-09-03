"""Normalize a bounded TC5 Avro pilot stream into an isolated SQLite schema."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from tc5_ingestion.avro_reader import records
from tc5_ingestion.normalize import normalize

SCHEMA = """
CREATE TABLE IF NOT EXISTS tc5_datasets(dataset_id TEXT PRIMARY KEY,dataset_name TEXT NOT NULL,publisher TEXT NOT NULL,collection_period TEXT NOT NULL,stream TEXT NOT NULL,platform TEXT NOT NULL,source_url TEXT NOT NULL,license TEXT NOT NULL,ground_truth_available INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tc5_events(id INTEGER PRIMARY KEY,source_event_id TEXT NOT NULL,dataset_id TEXT NOT NULL REFERENCES tc5_datasets(dataset_id),stream_id TEXT NOT NULL,event_type TEXT NOT NULL,timestamp TEXT,host TEXT,principal TEXT,process TEXT,file TEXT,network TEXT,raw_event_reference TEXT NOT NULL,raw_sha256 TEXT NOT NULL,raw_event_json TEXT NOT NULL,UNIQUE(dataset_id,stream_id,source_event_id,raw_sha256));
CREATE TABLE IF NOT EXISTS tc5_ground_truth_windows(id INTEGER PRIMARY KEY,dataset_id TEXT NOT NULL REFERENCES tc5_datasets(dataset_id),window_id TEXT NOT NULL,start_time TEXT,end_time TEXT,description TEXT,UNIQUE(dataset_id,window_id));
CREATE TABLE IF NOT EXISTS tc5_ground_truth_techniques(dataset_id TEXT NOT NULL,window_id TEXT NOT NULL,technique_id TEXT NOT NULL,source_reference TEXT,PRIMARY KEY(dataset_id,window_id,technique_id));
CREATE TABLE IF NOT EXISTS tc5_ground_truth_sources(dataset_id TEXT NOT NULL,title TEXT NOT NULL,url TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(dataset_id,url));
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True); connection=sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON"); connection.executescript(SCHEMA); return connection


def register(connection: sqlite3.Connection, dataset: dict, ground_truth: dict) -> None:
    connection.execute("INSERT OR REPLACE INTO tc5_datasets VALUES (?,?,?,?,?,?,?,?,?)",(
      dataset["dataset_id"],dataset["dataset_name"],dataset["publisher"],dataset["collection_period"],dataset["stream"],dataset["platform"],dataset["source_url"],dataset["license"],int(dataset["ground_truth_available"])))
    for window in ground_truth["attack_windows"]:
        connection.execute("INSERT OR REPLACE INTO tc5_ground_truth_windows(dataset_id,window_id,start_time,end_time,description) VALUES(?,?,?,?,?)",(dataset["dataset_id"],window["window_id"],window.get("start_time"),window.get("end_time"),window.get("description","")))
    for item in ground_truth["techniques"]:
        connection.execute("INSERT OR REPLACE INTO tc5_ground_truth_techniques VALUES(?,?,?,?)",(dataset["dataset_id"],item["window_id"],item["technique_id"],item.get("source_reference")))
    for source in ground_truth["source_references"]:
        connection.execute("INSERT OR REPLACE INTO tc5_ground_truth_sources VALUES(?,?,?,?)",(dataset["dataset_id"],source["title"],source["url"],source["status"]))
    connection.commit()


def ingest(path: Path, database: Path, dataset: dict, ground_truth: dict, stream_id: str, limit: int) -> tuple[int,int]:
    connection=connect(database); register(connection,dataset,ground_truth); inserted=duplicates=0
    try:
        for index, record in enumerate(records(path,limit)):
            item=normalize(record,dataset["dataset_id"],stream_id,path.name,index)
            before=connection.total_changes
            connection.execute("INSERT OR IGNORE INTO tc5_events(source_event_id,dataset_id,stream_id,event_type,timestamp,host,principal,process,file,network,raw_event_reference,raw_sha256,raw_event_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",tuple(item.values()))
            if connection.total_changes>before: inserted+=1
            else: duplicates+=1
        connection.commit(); return inserted,duplicates
    finally: connection.close()
