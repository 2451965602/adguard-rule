# AdGuard rules

This repository combines `user_rules.txt`, additions from `new_rules.txt`, and
enabled public filter URLs listed in `sources.txt` into `rules.txt`. New entries
are merged into `user_rules.txt` first, then combined with the subscriptions.
Exact duplicate non-empty lines are removed without rewriting rule semantics.

`user_rules.txt` contains only the `user_rules` list extracted from the local
AdGuardHome configuration. The rest of that configuration is not included.
Add rules to `new_rules.txt` to persist them into `user_rules.txt`. The file is
never cleared; repeated runs are idempotent and retain the pending entries.

Run locally with Python 3.10+:

```sh
python -m pip install -r requirements.txt
python merge_rules.py
python -m unittest discover -s tests
```

Every subscription must download and contain rules for an update to be written.
The generated outputs are replaced atomically only after all subscriptions
succeed. Filter directives are preserved only when they can be safely flattened.

Conditional blocks are checked for balance and preserved without deduplication.
Source-relative `!#include` directives and unknown bracketed sections are
rejected. The known `[Host 10007]` and `[Adblock Plus 2.0]` title lines are
converted to comments; other source rules are not rewritten.
YAML filters are parsed with PyYAML rather than interpreted as Python literals.

GitHub Actions runs every Monday and Thursday at 02:00 UTC and can also be
started manually. It commits changed `user_rules.txt` and `rules.txt`.
