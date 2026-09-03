import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mynewjob_app", ROOT / "backend" / "app.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class SemanticSearchTests(unittest.TestCase):
    def assert_finds(self, query, expected_title_part):
        offers = app.search_offers(query)
        self.assertTrue(
            any(expected_title_part.lower() in offer["title"].lower() for offer in offers),
            f"{query!r} n'a pas trouvé {expected_title_part!r}: {offers}",
        )

    def test_major_domain_aliases_find_relevant_offers(self):
        cases = {
            "cyber": "Cybersécurité",
            "cybersec": "SOC",
            "securite informatique": "Cybersécurité",
            "dev": "Développeur",
            "programmation": "Développeur",
            "informatique": "Systèmes & Réseaux",
            "analyse de donnees": "Data Analyst",
            "compta": "Comptable",
            "ressources humaines": "Recrutement",
            "juridique": "Juriste",
            "communication digitale": "Marketing",
            "graphisme": "Designer",
        }
        for query, title in cases.items():
            with self.subTest(query=query):
                self.assert_finds(query, title)

    def test_city_filter_remains_applied_after_semantic_expansion(self):
        offers = app.search_offers("cyber", "Arcueil")
        self.assertEqual(["Arcueil"], [offer["city"] for offer in offers])

    def test_semantic_results_stay_in_the_requested_domain(self):
        for query, expected_domain in {
            "cyber": "cybersecurite",
            "dev": "informatique",
            "compta": "finance",
            "rh": "rh",
            "juridique": "droit",
            "graphisme": "design",
        }.items():
            with self.subTest(query=query):
                offers = app.search_offers(query)
                self.assertTrue(offers)
                self.assertTrue(all(
                    app.detect_domain(offer["title"] + " " + offer["text"])[0] == expected_domain
                    for offer in offers
                ), offers)

    def test_external_provider_receives_canonical_domain(self):
        self.assertEqual("cybersécurité", app.canonical_search_query("cyber"))
        self.assertEqual("ressources humaines", app.canonical_search_query("rh"))


class SwipeCopyTests(unittest.TestCase):
    def test_swipe_actions_use_business_wording(self):
        html = (ROOT / "swipe.html").read_text(encoding="utf-8")
        self.assertIn('aria-label="Refuser"', html)
        self.assertIn('aria-label="Postuler"', html)
        self.assertIn('>REFUSER</span>', html)
        self.assertIn('>POSTULER</span>', html)
        self.assertIn("offre(s) à postuler", html)
        for forbidden in ('aria-label="Écarter"', 'aria-label="Suivre"', '>SUIVRE</span>', 'offre(s) suivie(s)'):
            self.assertNotIn(forbidden, html)

    def test_pointer_swipe_maps_left_to_refuse_and_right_to_apply(self):
        html = (ROOT / "swipe.html").read_text(encoding="utf-8")
        self.assertIn("dx < 0 ? 'no' : 'yes'", html)
        self.assertIn("dir === 'yes' ? 'fly-right' : 'fly-left'", html)


if __name__ == "__main__":
    unittest.main()
