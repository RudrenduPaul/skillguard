from skillguard.structural.typosquatting_check import (
    find_typosquat_matches,
    levenshtein_distance,
    load_known_names,
    parse_declared_name,
)


class TestParseDeclaredName:
    def test_extracts_the_declared_name_and_its_line_number(self):
        content = "---\nname: numpi\nnetwork: false\n---\nbody\n"
        declared = parse_declared_name(content)
        assert declared.name == "numpi"
        assert declared.line == 2

    def test_returns_none_when_no_frontmatter_block(self):
        assert parse_declared_name("# just a heading\n") is None

    def test_returns_none_when_no_name_field_is_declared(self):
        content = "---\nnetwork: false\nfilesystem: none\n---\nbody\n"
        assert parse_declared_name(content) is None

    def test_returns_none_for_an_empty_name_field(self):
        content = '---\nname: ""\n---\nbody\n'
        assert parse_declared_name(content) is None

    def test_returns_none_for_malformed_yaml_frontmatter(self):
        content = "---\nname: [unterminated\n---\nbody\n"
        assert parse_declared_name(content) is None


class TestLevenshteinDistance:
    def test_is_zero_for_identical_strings(self):
        assert levenshtein_distance("numpy", "numpy") == 0

    def test_counts_a_single_substitution_as_distance_1(self):
        assert levenshtein_distance("numpy", "numpi") == 1

    def test_counts_insertions_deletions_correctly(self):
        assert levenshtein_distance("flask", "flasky") == 1
        assert levenshtein_distance("", "abc") == 3
        assert levenshtein_distance("abc", "") == 3

    def test_handles_fully_unrelated_strings(self):
        assert levenshtein_distance("numpy", "zzzzz") == 5


class TestFindTyposquatMatches:
    known_names = ["numpy", "requests", "flask", "django"]

    def test_flags_a_near_miss_as_a_typosquat_match(self):
        matches = find_typosquat_matches("numpi", self.known_names)
        assert len(matches) == 1
        assert matches[0].known_name == "numpy"
        assert matches[0].distance == 1

    def test_does_not_flag_an_exact_match(self):
        assert find_typosquat_matches("numpy", self.known_names) == []
        assert find_typosquat_matches("NumPy", self.known_names) == []  # case-insensitive exact match

    def test_does_not_flag_an_unrelated_name(self):
        assert find_typosquat_matches("zzzxyzzy12345", self.known_names) == []

    def test_does_not_flag_short_names_even_at_edit_distance_1(self):
        assert find_typosquat_matches("cat", ["car", "cap"]) == []


class TestLoadKnownNames:
    def test_loads_the_real_bundled_seed_list(self):
        names = load_known_names()
        assert len(names) > 0
        assert "numpy" in names
        assert "skillguard" in names

    def test_fails_soft_returns_empty_list_for_a_missing_file(self):
        assert load_known_names("/nonexistent/known-names.json") == []
