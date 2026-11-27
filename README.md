# AdGuard rules

This repository combines the custom entries in `user_rules.txt` and enabled
public filter URLs listed in `sources.txt` into `rules.txt`. User rules appear
first; the merger keeps source order and original rule text, removes only exact
duplicate non-empty lines, and does not rewrite rule semantics.

`user_rules.txt` contains only the `user_rules` list extracted from the local
AdGuardHome configuration. The rest of that configuration is not included.

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

GitHub Actions runs every Monday and Thursday at 02:00 UTC and can also be
started manually. It commits `rules.txt` only when the generated file changes.
