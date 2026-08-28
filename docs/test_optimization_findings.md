# Python Test Optimization Findings - SentinelNet

## 1. Executive Summary & Baseline Metrics

- **Current Suite:** 1,910 tests across 130 test files.
- **Execution Time:** ~398.99s (~6.65 minutes) running sequentially on Windows via `unittest discover`.
- **Primary Bottleneck:** Single-threaded execution + disk-bound SQLite temp databases on Windows NTFS + CPU-bound crypto operations + unmocked timers/sleeps.
- **Target Execution Time:** ~30s – 50s (8x–12x speedup) with zero test compromises.

---

## 2. Identified Bottlenecks & Detailed Root Causes

### A. Single-Threaded Sequential Runner
- **Current State:** `uv run python -m unittest discover -s tests` runs entirely in a single Python process on one CPU core.
- **Root Cause:** Standard library `unittest` does not support multi-process test distribution out of the box. On multi-core modern CPUs (8–16 cores), 85–90% of compute capacity sits idle during test runs.

### B. SQLite Disk I/O Overhead on Windows NTFS
- **Current State:** Test suites (e.g. `test_jump_site.py`, `test_db.py`, `test_ui_revamp.py`, `test_baseline.py`) create temporary directories (`tempfile.mkdtemp`) and read/write SQLite `.db` files to disk.
- **Root Cause:** Windows NTFS filesystem incurs synchronous flush and metadata locking overhead for database transactions. SQLite default settings (`PRAGMA synchronous = FULL; PRAGMA journal_mode = DELETE`) force disk syncs on every commit.

### C. Bcrypt / Cryptographic Hashing Work Factor
- **Current State:** Identity, session, and RBAC tests hash passwords or verify hashes across dozens of test fixtures.
- **Root Cause:** Standard bcrypt work factor (`rounds=12`) deliberately consumes ~150–250ms of CPU per hash to prevent brute-force attacks in production. In a test suite running hundreds of auth checks, this adds dozens of seconds of pure CPU spinning.

### D. Unmocked Sleep Calls & Polling Waits
- **Current State:** Several test modules call explicit `time.sleep()` to wait for background threads or simulated timers:
  - `tests/test_observability_ingest.py`: `time.sleep(0.6)`, `time.sleep(0.5)`
  - `tests/test_remote_site.py`: `time.sleep(0.1)`, `time.sleep(0.2)`
  - `tests/test_db.py`: `time.sleep(0.05)`, `time.sleep(0.2)`
  - `tests/test_scan_verify.py`: `time.sleep(0.05)`
- **Impact:** Each sleep adds mandatory physical latency to the test run, blocking the thread completely.

### E. Redundant File I/O and Template Parsing in UI Tests
- **Current State:** Large test suites like `tests/test_ui_revamp.py` (3,036 lines), `tests/test_client_diagnosis.py` (1,200+ lines), and `tests/test_router_parity.py` parse templates and static CSS/JS repeatedly inside individual test methods.
- **Root Cause:** Lack of module-level or class-level caching (`setUpClass`) for immutable rendered static assets and HTML DOM fixtures.

---

## 3. High-Impact Solutions & Recommended Implementation

### Option 1: Parallel Test Execution via `pytest-xdist` (Impact: 5x – 8x speedup)
Because all existing tests are standard `unittest.TestCase` classes, `pytest` executes them out of the box without changing test logic.

- **Setup:**
  ```toml
  # Add to dev dependencies:
  pytest >= 8.0.0
  pytest-xdist >= 3.5.0
  ```
- **Execution Command:**
  ```sh
  uv run pytest tests -n auto
  ```
- **Consideration:** Ensure tests using `SENTINELNET_DATA_DIR` create isolated temporary folders per worker process or per test class (already largely done via `tempfile.mkdtemp()`).

---

### Option 2: Optimize Test SQLite DB Configuration (Impact: 2x – 3x I/O speedup)
Configure test databases to operate with in-memory journaling and zero disk syncs.

- **Code Pattern:**
  ```python
  # When opening connection in test fixtures:
  conn = sqlite3.connect(":memory:") # or disk path with test pragmas:
  conn.execute("PRAGMA synchronous = OFF")
  conn.execute("PRAGMA journal_mode = MEMORY")
  conn.execute("PRAGMA temp_store = MEMORY")
  ```

---

### Option 3: Monkeypatch Bcrypt Rounds for Test Environment (Impact: 10x auth speedup)
Reduce bcrypt workload from 12 rounds to minimum 4 rounds during test runs.

- **Code Pattern:**
  ```python
  # In tests/__init__.py or test bootstrap fixture:
  import bcrypt

  _orig_gensalt = bcrypt.gensalt
  def _fast_gensalt(rounds=4, prefix=b"2b"):
      return _orig_gensalt(rounds=4, prefix=prefix)

  bcrypt.gensalt = _fast_gensalt
  ```
- **Result:** Drops hashing time from ~180ms down to <1ms per password.

---

### Option 4: Mock Real Time Waits / Event-Based Synchronization (Impact: Eliminates ~5-10s wasted wait time)
Replace hardcoded `time.sleep` with mock patches or `threading.Event().wait(timeout=...)`.

- **Code Pattern:**
  ```python
  from unittest.mock import patch

  @patch("time.sleep", return_value=None)
  def test_something(self, mock_sleep):
      ...
  ```

---

### Option 5: Cache Rendered HTML and Static Assets (Impact: 20-30% faster UI tests)
Load CSS/HTML once per test class rather than per test method.

- **Code Pattern:**
  ```python
  class TestUiRevamp(unittest.TestCase):
      @classmethod
      def setUpClass(cls):
          super().setUpClass()
          with open("static/css/dashboard.css", encoding="utf-8") as f:
              cls.cached_css = f.read()
  ```

---

## 4. Quick Wins Matrix

| Optimization | Implementation Effort | Estimated Speedup | Risk / Side Effects |
| :--- | :---: | :---: | :--- |
| **`pytest -n auto`** | Low (add dev dependency) | **60% – 80% reduction** (~60s total) | Need per-process DB isolation |
| **Bcrypt rounds=4 patch** | Very Low (5 lines in `tests/__init__.py`) | **10% – 15% reduction** | None for unit tests |
| **SQLite PRAGMAs (sync=OFF)** | Low | **15% – 25% reduction** | None for test DBs |
| **Mocking `time.sleep`** | Low | **5% – 10% reduction** | None |
| **Selective testing (dev loop)**| Zero | **Instant (1–3s per file)** | None |

---

## 5. Development Workflow Recommendations

1. **Daily local loop:**
   Run only the test file you are editing:
   ```sh
   uv run python -m unittest tests.test_wlc_service
   ```
2. **Pre-commit full verification:**
   Run parallel test suite across all CPU cores:
   ```sh
   uv run pytest tests -n auto
   ```
3. **Pinpoint slow tests dynamically:**
   ```sh
   uv run pytest tests --durations=20
   ```
