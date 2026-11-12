# Feedback task starting environment

Upstream: https://github.com/pyca/pyopenssl
Upstream commit: `1487da3773b0db3977353c9e379ad74124002c43`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_ssl.py -k 'test_bio_write or test_bio_read or test_set_verify_default_callback'
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `11 passed, 246 deselected, 9 warnings in 0.23s`
Whole-command wall time: 1.290 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
