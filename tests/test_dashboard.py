"""Regression test for the embedded dashboard page (run from the project root).

Catches the mistakes that cannot be seen on the device until you click: duplicate element ids (getElementById would
silently return the wrong element), ids used by the script but missing from the page, form fields that the script reads
but that are not inputs/selects, and JavaScript syntax errors.
"""
import collections
import re
import shutil
import subprocess
import sys

src = open("src/web_ui.h", encoding="utf-8").read()
page = src[src.index("static const char DASH_PAGE"):]
ids = re.findall(r"\bid=([A-Za-z0-9_]+)", page)
js = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
used = set(re.findall(r"\$\('([A-Za-z0-9_]+)'\)", js))
problems = []

dups = sorted(i for i, c in collections.Counter(ids).items() if c > 1)
if dups:
    problems.append("duplicate ids: %s" % dups)
missing = sorted(i for i in used if i not in ids)
if missing:
    problems.append("ids used by the script but missing from the page: %s" % missing)

# every field that saveCfg() sends must be a single input or select
m = re.search(r"async function saveCfg\(\)\{.*?\[(.*?)\]\.forEach", js, re.S)
fields = re.findall(r"'([a-z0-9]+)'", m.group(1))
for f in fields:
    tag = re.search(r"<(input|select)\b[^>]*\bid=%s\b" % f, page)
    if not tag:
        problems.append("saveCfg sends '%s' but there is no <input>/<select> with that id" % f)

if shutil.which("node"):
    open("/tmp/c3hole_dash.js", "w").write(js)
    r = subprocess.run(["node", "--check", "/tmp/c3hole_dash.js"], capture_output=True, text=True)
    if r.returncode:
        problems.append("JavaScript syntax error: " + r.stderr.strip().splitlines()[0])
else:
    print("(node not found: JavaScript syntax check skipped)")

if problems:
    print("DASHBOARD TEST FAILED:\n  " + "\n  ".join(problems))
    sys.exit(1)
print("dashboard test OK: %d ids unique, %d referenced, %d settings fields are real controls" % (len(ids), len(used), len(fields)))
