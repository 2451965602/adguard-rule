# AdGuard rules

This repository combines the enabled public filter URLs listed in `sources.txt`
into `rules.txt`. The merger keeps source order and original rule text, removes
only exact duplicate non-empty lines, and does not rewrite rule semantics.

Run locally with Python 3.10+:

```sh
python -m pip install -r requirements.txt
python merge_rules.py
python -m unittest discover -s tests
```

Every source must download and contain rules for an update to be written. The
output is replaced atomically only after all sources succeed. Filter directives
are preserved only when they can be safely flattened.

Conditional blocks are checked for balance and preserved without deduplication.
Source-relative `!#include` directives and unknown bracketed sections are
rejected. The known `[Host 10007]` and `[Adblock Plus 2.0]` title lines are
converted to comments; other source rules are not rewritten.
YAML filters are parsed with PyYAML rather than interpreted as Python literals.

GitHub Actions runs on the 1st, 4th, 7th, and subsequent every-third calendar
day of each month at 02:00 UTC (the interval across month boundaries may differ
from three days), and can also be started manually. It commits `rules.txt` only
when the generated file changes.
