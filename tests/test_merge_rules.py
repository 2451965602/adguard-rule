import tempfile
import unittest
from pathlib import Path
import merge_rules


class MergeRulesTests(unittest.TestCase):
    def test_deduplicates_exact_lines_and_preserves_order_and_directives(self):
        sources = ["one", "two"]
        contents = {
            "one": ["! comment", "||example.com^", "!#include other.txt"],
            "two": ["||example.com^", "@@||allowed.example^", "||example.com^ "],
        }
        self.assertEqual(
            merge_rules.merge_sources(sources, contents.__getitem__),
            ["! comment", "||example.com^", "!#include other.txt",
             "@@||allowed.example^", "||example.com^ "],
        )

    def test_unwraps_yaml_rules_without_rewriting_rule_text(self):
        self.assertEqual(
            merge_rules.extract_rules(
                "name: test\nrules:\n  - '||example.com^$important'\n  - '!#include x'\n"
            ),
            ["||example.com^$important", "!#include x"],
        )

    def test_uses_yaml_quoting_rules_not_python_literal_rules(self):
        self.assertEqual(
            merge_rules.extract_rules("rules:\n  - '||foo''bar.example^'\n"),
            ["||foo'bar.example^"],
        )

    def test_failure_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "rules.txt"
            output.write_text("previous\n", encoding="utf-8")

            def fail(_url):
                raise RuntimeError("network failure")

            with self.assertRaises(RuntimeError):
                rules = merge_rules.merge_sources(["broken"], fail)
                merge_rules.atomic_write(output, rules)
            self.assertEqual(output.read_text(encoding="utf-8"), "previous\n")

    def test_conditional_rules_are_not_deduplicated_across_scopes(self):
        sources = ["first", "second"]
        content = {
            "first": ["!#if A", "||same.example^", "!#endif"],
            "second": ["!#if B", "||same.example^", "!#endif"],
        }
        self.assertEqual(
            merge_rules.merge_sources(sources, content.__getitem__),
            ["!#if A", "||same.example^", "!#endif",
             "!#if B", "||same.example^", "!#endif"],
        )

    def test_user_rules_are_kept_first_and_exact_duplicates_removed(self):
        user_rules = [
            "# user exception",
            "@@||allow.example^$important",
            "||block.example^$important",
        ]
        feed = [
            "@@||allow.example^$important",
            "||block.example^$important",
            "||feed-only.example^",
        ]
        self.assertEqual(
            merge_rules.merge_sources(
                ["feed"], {"feed": feed}.__getitem__, local_rules=user_rules
            ),
            user_rules + ["||feed-only.example^"],
        )

    def test_reads_local_rule_file_without_rewriting_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "user_rules.txt"
            expected = ["# marker", "@@||allowed.example^$important", "||blocked.example^"]
            path.write_text("\n".join(expected) + "\n", encoding="utf-8")
            self.assertEqual(merge_rules.read_local_rules(path), expected)

    def test_rejects_unbalanced_conditionals_and_source_relative_includes(self):
        for rules in (["!#if A", "||example.com^"], ["!#include fragments/extra.txt"]):
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                merge_rules.validate_filter_lines(rules)

    def test_rejects_source_specific_host_sections(self):
        converted = merge_rules.convert_known_titles(
            ["[Host 10007]", "[Adblock Plus 2.0]", "||example.com^"]
        )
        self.assertEqual(
            converted,
            ["! [Host 10007]", "! [Adblock Plus 2.0]", "||example.com^"],
        )
        merge_rules.validate_filter_lines(converted)

    def test_rejects_unknown_bracketed_sections(self):
        with self.assertRaisesRegex(ValueError, "bracketed section"):
            merge_rules.validate_filter_lines(["[Host 99999]", "||example.com^"])

    def test_reports_all_failed_sources_without_returning_partial_list(self):
        def fail(url):
            raise RuntimeError("unavailable")

        with self.assertRaisesRegex(RuntimeError, "first[\\s\\S]*second"):
            merge_rules.merge_sources(["first", "second"], fail)

    def test_rejects_non_https_sources(self):
        with self.assertRaises(ValueError):
            merge_rules.validate_url("http://example.com/rules.txt")


if __name__ == "__main__":
    unittest.main()
