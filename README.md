# AdGuard rules

This repository combines `user_rules.txt`, additions from `new_rules.txt`, and
enabled public filter URLs listed in `sources.txt` into `rules.txt`. New entries
are merged into `user_rules.txt` first, then combined with the subscriptions.
Exact duplicate non-empty lines are removed without rewriting rule semantics.

`user_rules.txt` contains only the `user_rules` list extracted from the local
AdGuardHome configuration. The rest of that configuration is not included.
Add pending rules to `new_rules.txt`. After subscriptions validate and both
output files are written successfully, the queue is cleared only if its contents
have not changed since processing began. Failed downloads/writes leave pending
rules available for retry; concurrent edits are preserved and should be merged
on the next run. Exact duplicates are idempotent.

Run locally with Python 3.10+:

```sh
python -m pip install -r requirements.txt
python merge_rules.py
python -m unittest discover -s tests
```

Every subscription must download and contain rules before output updates begin.
Each generated output is replaced atomically; the input queue is cleared only
after both output writes succeed and its snapshot is still unchanged. If the
`rules.txt` write fails after updating `user_rules.txt`, the pending input stays
in place and a retry safely deduplicates it. Filter directives are preserved
only when they can be safely flattened.

Conditional blocks are checked for balance and preserved without deduplication.
Source-relative `!#include` directives and unknown bracketed sections are
rejected. The known `[Host 10007]` and `[Adblock Plus 2.0]` title lines are
converted to comments; other source rules are not rewritten.
YAML filters are parsed with PyYAML rather than interpreted as Python literals.

GitHub Actions runs every Monday and Thursday at 02:00 UTC and can also be
started manually. It commits changed `user_rules.txt` and `rules.txt`.
It also commits `new_rules.txt` when a successful run clears its queued entries.
