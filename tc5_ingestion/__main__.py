"""Inspect, normalize, and validate a bounded DARPA TC5 pilot."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from tc5_ingestion.avro_reader import inspect_file
from tc5_ingestion.metadata import load_dataset, load_ground_truth
from tc5_ingestion.parser import ingest

ROOT=Path(__file__).resolve().parents[1]
DATASET_ID="DARPA-TC5-FIVEDIRECTIONS-PILOT"


def validate(database: Path, dataset_id: str) -> dict:
    if not database.is_file(): raise ValueError(f"database not found: {database}")
    connection=sqlite3.connect(database)
    try:
        dataset=connection.execute("SELECT COUNT(*) FROM tc5_datasets WHERE dataset_id=?",(dataset_id,)).fetchone()[0]
        events=connection.execute("SELECT COUNT(*) FROM tc5_events WHERE dataset_id=?",(dataset_id,)).fetchone()[0]
        valid=connection.execute("SELECT COUNT(*) FROM tc5_events WHERE dataset_id=? AND source_event_id<>'' AND event_type<>'' AND raw_event_reference<>'' AND length(raw_sha256)=64",(dataset_id,)).fetchone()[0]
        sources=connection.execute("SELECT COUNT(*) FROM tc5_ground_truth_sources WHERE dataset_id=?",(dataset_id,)).fetchone()[0]
        unknown=connection.execute("SELECT COUNT(*) FROM tc5_events WHERE dataset_id=? AND event_type='Unknown'",(dataset_id,)).fetchone()[0]
    finally: connection.close()
    return {"dataset_registered":dataset==1,"events":events,"valid_provenance":valid,"unknown_types":unknown,"ground_truth_sources":sources,"valid":dataset==1 and events>0 and events==valid}


def main(argv=None)->int:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("command",choices=("inspect","normalize","validate"))
    parser.add_argument("--input",type=Path); parser.add_argument("--database",type=Path,default=ROOT/"data/tc5.db")
    parser.add_argument("--registry",type=Path,default=ROOT/"data/metadata/datasets.json"); parser.add_argument("--ground-truth",type=Path,default=ROOT/"ground_truth/tc5_windows_pilot.json")
    parser.add_argument("--dataset-id",default=DATASET_ID); parser.add_argument("--stream-id",default="fivedirections-1-pilot"); parser.add_argument("--limit",type=int,default=10000)
    args=parser.parse_args(argv)
    try:
        if args.command in {"inspect","normalize"} and args.input is None: parser.error("--input is required")
        if args.command=="inspect": result=inspect_file(args.input,min(args.limit,1000))
        elif args.command=="normalize":
            dataset=load_dataset(args.registry,args.dataset_id); truth=load_ground_truth(args.ground_truth,args.dataset_id)
            inserted,duplicates=ingest(args.input,args.database,dataset,truth,args.stream_id,args.limit)
            result={"dataset_id":args.dataset_id,"stream_id":args.stream_id,"inserted":inserted,"duplicates":duplicates,"database":str(args.database)}
        else: result=validate(args.database,args.dataset_id)
    except (OSError,ValueError,json.JSONDecodeError,sqlite3.Error) as exc: parser.error(str(exc))
    print(json.dumps(result,indent=2,sort_keys=True)); return 0


if __name__=="__main__": raise SystemExit(main())
