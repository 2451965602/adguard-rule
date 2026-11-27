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

    def test_empty_new_rules_file_is_kept_and_does_not_change_user_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user = root / "user_rules.txt"
            new = root / "new_rules.txt"
            output = root / "rules.txt"
            user.write_text("||existing.example^\n", encoding="utf-8")
            new.write_bytes(b"")
            original_user = user.read_bytes()

            merge_rules.update_rule_files(
                user, new, output, ["feed"], fetch=lambda _: ["||feed.example^"]
            )

            self.assertEqual(user.read_bytes(), original_user)
            self.assertEqual(new.read_bytes(), b"")
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "||existing.example^\n||feed.example^\n",
            )

    def test_new_rules_are_exactly_deduplicated_and_repeated_runs_are_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user = root / "user_rules.txt"
            new = root / "new_rules.txt"
            output = root / "rules.txt"
            user.write_text(
                "||existing.example^\n@@||allow.example^$important\n",
                encoding="utf-8",
            )
            new_content = (
                "||existing.example^\n"
                "@@||allow.example^$important\n"
                "||new.example^\n"
                "||new.example^\n"
            )
            new.write_text(new_content, encoding="utf-8")
            fetch = lambda _: ["||new.example^", "||feed-only.example^"]

            merge_rules.update_rule_files(user, new, output, ["feed"], fetch=fetch)
            first_user = user.read_bytes()
            first_output = output.read_bytes()
            merge_rules.update_rule_files(user, new, output, ["feed"], fetch=fetch)

            self.assertEqual(user.read_bytes(), first_user)
            self.assertEqual(output.read_bytes(), first_output)
            self.assertEqual(new.read_text(encoding="utf-8"), new_content)
            self.assertEqual(
                user.read_text(encoding="utf-8").splitlines(),
                [
                    "||existing.example^",
                    "@@||allow.example^$important",
                    "||new.example^",
                ],
            )
            self.assertEqual(
                output.read_text(encoding="utf-8").splitlines().count("||new.example^"),
                1,
            )

    def test_new_rules_update_adds_new_rule_without_removing_persisted_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user = root / "user_rules.txt"
            new = root / "new_rules.txt"
            output = root / "rules.txt"
            user.write_text("||base.example^\n", encoding="utf-8")
            new.write_text("||version-one.example^\n", encoding="utf-8")
            fetch = lambda _: []

            merge_rules.update_rule_files(user, new, output, [], fetch=fetch)
            new.write_text("||version-two.example^\n", encoding="utf-8")
            merge_rules.update_rule_files(user, new, output, [], fetch=fetch)

            self.assertEqual(
                user.read_text(encoding="utf-8").splitlines(),
                [
                    "||base.example^",
                    "||version-one.example^",
                    "||version-two.example^",
                ],
            )
            self.assertEqual(new.read_text(encoding="utf-8"), "||version-two.example^\n")

    def test_conditional_new_rules_are_preserved_once_across_repeated_runs(self):
        additions = ["!#if A", "||conditional.example^", "!#endif"]
        once = merge_rules.merge_user_rules(["||base.example^"], additions)
        twice = merge_rules.merge_user_rules(once, additions)
        self.assertEqual(once, ["||base.example^"] + additions)
        self.assertEqual(twice, once)

    def test_conditional_new_rules_keep_scope_during_full_update(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user = root / "user_rules.txt"
            new = root / "new_rules.txt"
            output = root / "rules.txt"
            user.write_text("||base.example^\n", encoding="utf-8")
            additions = ["!#if A", "||conditional.example^", "!#endif"]
            new.write_text("\n".join(additions) + "\n", encoding="utf-8")
            fetch = lambda _: ["||conditional.example^", "||feed.example^"]

            merge_rules.update_rule_files(user, new, output, ["feed"], fetch=fetch)
            first_user = user.read_bytes()
            first_output = output.read_bytes()
            merge_rules.update_rule_files(user, new, output, ["feed"], fetch=fetch)

            self.assertEqual(user.read_bytes(), first_user)
            self.assertEqual(output.read_bytes(), first_output)
            self.assertEqual(new.read_text(encoding="utf-8").splitlines(), additions)
            self.assertEqual(output.read_text(encoding="utf-8").splitlines().count(
                "||conditional.example^"
            ), 2)

    def test_download_failure_leaves_all_persistent_files_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user = root / "user_rules.txt"
            new = root / "new_rules.txt"
            output = root / "rules.txt"
            user.write_text("||base.example^\n", encoding="utf-8")
            new.write_text("||pending.example^\n", encoding="utf-8")
            output.write_text("previous output\n", encoding="utf-8")
            originals = (user.read_bytes(), new.read_bytes(), output.read_bytes())

            def fail(_):
                raise RuntimeError("subscription unavailable")

            with self.assertRaisesRegex(RuntimeError, "no output written"):
                merge_rules.update_rule_files(user, new, output, ["broken"], fetch=fail)

            self.assertEqual(
                (user.read_bytes(), new.read_bytes(), output.read_bytes()),
                originals,
            )

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
