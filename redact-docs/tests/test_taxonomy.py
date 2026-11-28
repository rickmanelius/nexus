"""The PII definition: the JSON taxonomy, the prose doc and the answer key agree."""
import os
import re
import unittest

from helpers import DOCS, UNIT, config, taxonomy

import leakcheck  # noqa: E402


class TaxonomyTest(unittest.TestCase):
    def setUp(self):
        self.tax = taxonomy()
        self.ids = [c["id"] for c in self.tax["classes"]]
        with open(os.path.join(DOCS, "pii-definition.md"), encoding="utf-8") as f:
            self.doc = f.read()

    def test_doc_and_json_name_the_same_classes(self):
        in_doc = re.findall(r"^### `([A-Z][A-Z0-9_]*)`", self.doc, re.M)
        self.assertEqual(sorted(in_doc), sorted(self.ids))

    def test_doc_states_each_class_tier_and_placeholder(self):
        for c in self.tax["classes"]:
            line = f"{c['name']}. Tier {c['tier']}, placeholder `[{c['tag']}_n]`, caught by {', '.join(c['layers'])}."
            self.assertIn(line, self.doc, c["id"])

    def test_ids_and_tags_are_unique_and_upper_case(self):
        tags = [c["tag"] for c in self.tax["classes"]]
        self.assertEqual(len(self.ids), len(set(self.ids)))
        self.assertEqual(len(tags), len(set(tags)))
        for value in self.ids + tags:
            self.assertRegex(value, r"^[A-Z][A-Z0-9_]*$")

    def test_every_class_is_complete(self):
        for c in self.tax["classes"]:
            for field in ("tier", "name", "definition", "examples", "counter_examples", "layers", "match",
                          "components", "labels", "classifier_labels"):
                self.assertIn(field, c, f"{c['id']} lacks {field}")
            self.assertIn(c["tier"], ("A", "B", "H"))
            self.assertIn(c["match"], ("text", "name", "digits", "casefold"))
            self.assertIn(c["components"], ("whole", "name_tokens", "digits", "address"))
            for pattern in c["labels"] + c.get("field_labels", []):
                re.compile(pattern, re.I)

    def test_secrets_are_tier_a_and_never_reach_the_models(self):
        cfg = config()
        for cid in ("CREDENTIAL", "SECRET", "SEED_PHRASE"):
            self.assertEqual(cfg.classes[cid]["tier"], "A")
            self.assertIn(cid, cfg.active)
        for cid in ("SECRET", "SEED_PHRASE"):
            self.assertEqual(cfg.classes[cid]["layers"], ["rules"])

    def test_answer_key_rows_all_carry_a_known_class(self):
        key = leakcheck.load_key(os.path.join(UNIT, "selftest", "pii-answer-key.md"))
        self.assertEqual(len(key), 133)
        for row in key:
            self.assertIn(row["cls"], self.ids, f"row {row['n']}")


if __name__ == "__main__":
    unittest.main()
