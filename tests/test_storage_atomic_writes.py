import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from backend.utils.storage import _write_json


class AtomicStorageWriteTests(unittest.TestCase):
    def test_concurrent_replacements_never_expose_partial_json_or_share_tempfile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "project.json"

            def write(index: int):
                _write_json(target, {"write_id": index, "payload": [index] * 100})

            with ThreadPoolExecutor(max_workers=12) as executor:
                list(executor.map(write, range(60)))

            saved = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(saved["payload"], [saved["write_id"]] * 100)
            self.assertEqual(list(Path(temp_dir).glob("*.tmp")), [])
            self.assertEqual(list(Path(temp_dir).glob(".*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
