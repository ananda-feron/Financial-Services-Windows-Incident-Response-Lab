import gzip,json,tempfile,unittest
from pathlib import Path
from fastavro import writer
from tc5_ingestion.__main__ import validate
from tc5_ingestion.avro_reader import inspect_file,records
from tc5_ingestion.metadata import load_dataset,load_ground_truth
from tc5_ingestion.normalize import normalize,timestamp
from tc5_ingestion.parser import ingest

ROOT=Path(__file__).parents[2]
SCHEMA={"type":"record","name":"TCCDMDatum","fields":[{"name":"datum","type":{"type":"record","name":"Event","fields":[{"name":"uuid","type":"bytes"},{"name":"timestampNanos","type":"long"},{"name":"subject","type":"string"},{"name":"predicateObject","type":"string"},{"name":"hostId","type":["null","string"],"default":None}]}}]}
EVENT={"datum":{"uuid":b"event-1","timestampNanos":1557316800000000000,"subject":"subject-1","predicateObject":"file-1","hostId":"windows-host-1"}}

class TC5PilotTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name); raw=self.root/"pilot.avro"
  with raw.open("wb") as output: writer(output,SCHEMA,[EVENT])
  self.gz=self.root/"pilot.bin.1.gz"
  with raw.open("rb") as source,gzip.open(self.gz,"wb") as output: output.write(source.read())
  self.registry=ROOT/"data/metadata/datasets.json"; self.truth=ROOT/"ground_truth/tc5_windows_pilot.json"
 def tearDown(self): self.temp.cleanup()
 def test_reads_gzip_avro_container(self): self.assertEqual(1,len(list(records(self.gz))))
 def test_inspects_types_and_fields(self):
  result=inspect_file(self.gz); self.assertEqual(1,result["records_inspected"]); self.assertEqual({"Event":1},result["types"])
 def test_normalizes_timestamp_and_provenance_deterministically(self):
  first=normalize(EVENT,"dataset","stream",self.gz.name,0); second=normalize(EVENT,"dataset","stream",self.gz.name,0)
  self.assertEqual("2019-05-08T12:00:00Z",first["timestamp"]); self.assertEqual(first,second); self.assertEqual(64,len(first["raw_sha256"]))
 def test_invalid_timestamp_is_rejected(self):
  with self.assertRaisesRegex(ValueError,"invalid timestampNanos"): timestamp("not-time")
 def test_metadata_and_ground_truth_are_separate(self):
  dataset=load_dataset(self.registry,"DARPA-TC5-FIVEDIRECTIONS-PILOT"); truth=load_ground_truth(self.truth,dataset["dataset_id"])
  self.assertTrue(dataset["ground_truth_available"]); self.assertNotIn("attack_windows",dataset); self.assertIn("attack_windows",truth)
 def test_ingestion_is_idempotent_and_validates_provenance(self):
  dataset=load_dataset(self.registry,"DARPA-TC5-FIVEDIRECTIONS-PILOT"); truth=load_ground_truth(self.truth,dataset["dataset_id"]); database=self.root/"tc5.db"
  self.assertEqual((1,0),ingest(self.gz,database,dataset,truth,"pilot",100)); self.assertEqual((0,1),ingest(self.gz,database,dataset,truth,"pilot",100)); self.assertTrue(validate(database,dataset["dataset_id"])["valid"])
 def test_malformed_avro_is_rejected(self):
  bad=self.root/"bad.avro"; bad.write_bytes(b"not-avro")
  with self.assertRaisesRegex(ValueError,"cannot read Avro"): list(records(bad))

if __name__=="__main__": unittest.main()
