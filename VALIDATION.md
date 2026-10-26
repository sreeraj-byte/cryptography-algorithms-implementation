# Standalone project validation

Validated 27 October 2026 using Python 3.12.14 on Linux.

`python -m pytest -q`: **16 passed**.

AES/RSA hybrid round trips, wrong passwords/keys, tampering, malformed envelopes, SHA-256 vector, output overwrite protection, CLI workflows, standalone hash dashboard, and RSA dashboard key generation checked.

The standalone app imports only its own project module. There is no dependency
on the other project folder. See `tested_versions.txt` for direct dependency
versions. Native macOS/Windows setup and manual browser file upload/download
were not tested here; dashboard interactions use Streamlit AppTest.
