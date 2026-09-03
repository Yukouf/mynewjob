import importlib.util
import pathlib
import unittest
from io import BytesIO
from pypdf import PdfReader

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
            "vente": "Commercial",
            "commerce": "Business Developer",
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
            "vente": "vente",
        }.items():
            with self.subTest(query=query):
                offers = app.search_offers(query)
                self.assertTrue(offers)
                self.assertTrue(all(
                    app.detect_domain(offer["title"] + " " + offer["text"])[0] == expected_domain
                    for offer in offers
                ), offers)

    def test_every_domain_resolves_to_its_own_offers(self):
        for domain in app.DOMAIN_ALIASES:
            alias = app.DOMAIN_ALIASES[domain][0]
            offers = app.search_offers(alias)
            self.assertTrue(offers, f"{domain}: aucun résultat pour {alias!r}")
            wrong = [o for o in offers if app.detect_domain(o["title"] + " " + o["text"])[0] != domain]
            self.assertFalse(wrong, f"{domain}: offres mal classées {[o['title'] for o in wrong]}")

    def test_external_provider_receives_canonical_domain(self):
        self.assertEqual("cybersécurité", app.canonical_search_query("cyber"))
        self.assertEqual("ressources humaines", app.canonical_search_query("rh"))

    def test_ats_analysis_returns_score_and_domain_keywords(self):
        analysis = app.analyze_ats(
            "Analyste SOC avec expérience Wazuh, SIEM et réponse aux incidents. "
            "Compétences et expériences professionnelles. Formation Master.",
            "cybersecurite",
        )
        self.assertGreaterEqual(analysis["score"], 1)
        self.assertIn("wazuh", analysis["mots_cles_presents"])
        self.assertIn("soc", analysis["mots_cles_presents"])
        self.assertTrue(analysis["mots_cles_a_valider"])
        self.assertLess(analysis["score"], 100)
        self.assertTrue(all(k not in analysis["mots_cles_presents"] for k in analysis["mots_cles_a_valider"]))

    def test_ats_score_cannot_be_perfect_when_domain_keywords_are_missing(self):
        keywords = app.DOMAIN_KEYWORDS["cybersecurite"][:-1]
        text = "Expérience Formation Compétences candidat@example.com " + " ".join(keywords)
        analysis = app.analyze_ats(text, "cybersecurite")
        self.assertTrue(analysis["mots_cles_a_valider"])
        self.assertLess(analysis["score"], 100)

    def test_ats_pdf_contains_rewritten_content_and_validated_keywords(self):
        content = "Youssef Exemple\nAnalyste SOC\nEXPÉRIENCE\nSupervision Wazuh.\nFORMATION\nMaster cybersécurité."
        pdf = app.build_ats_pdf(content, ["SIEM", "réponse aux incidents"])
        self.assertTrue(pdf.startswith(b"%PDF"))
        extracted = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(pdf)).pages)
        self.assertIn("Youssef Exemple", extracted)
        self.assertIn("COMPÉTENCES CIBLÉES", extracted)
        self.assertIn("réponse aux incidents", extracted)

    def test_fallback_rewrite_preserves_source_facts(self):
        source = "Youssef Exemple\nTrois ans chez Exemple SA\nWazuh et Suricata"
        rewritten = app.fallback_rewrite_cv(source)
        self.assertIn("Trois ans chez Exemple SA", rewritten)
        self.assertIn("Wazuh et Suricata", rewritten)


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

    def test_cv_import_proposes_ats_keywords(self):
        html = (ROOT / "swipe.html").read_text(encoding="utf-8")
        self.assertIn('id="ats-box"', html)
        self.assertIn('id="ats-score"', html)
        self.assertIn('id="ats-missing"', html)
        self.assertIn('onclick="copyAtsKeywords()"', html)
        self.assertIn('onclick="generateAtsCv()"', html)
        self.assertIn('id="ats-generate"', html)
        self.assertIn("Générer mon CV ATS", html)
        self.assertIn("Mots-clés à valider", html)


if __name__ == "__main__":
    unittest.main()
