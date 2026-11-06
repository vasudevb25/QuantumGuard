"""Keep the test suite away from the real project state.

The project's paths are relative to the working directory, so tests run from
the repo root used to write to the real graphs/ and open the real key store:
a run replaced graphs/provenance_graph.gpickle with a 2-event fixture, and a
locked key store made Phase 7 tests fail. Import this before anything from the
project. Importing it moves the process into a temporary directory and selects
the file store.
"""
import atexit
import os
import shutil
import tempfile

_directory = tempfile.mkdtemp(prefix="quantumguard-tests-")
atexit.register(shutil.rmtree, _directory, ignore_errors=True)
os.chdir(_directory)
os.environ["QG_STORE"] = "file"
os.environ.pop("QG_KEYSTORE_PASSPHRASE", None)
