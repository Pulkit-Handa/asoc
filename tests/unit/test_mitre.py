from agents.shared.mitre import get_techniques_for_category, get_technique_name


def test_get_techniques_for_category_valid():
    """Test that a valid category returns the expected list of technique IDs."""
    techniques = get_techniques_for_category("Initial Access")
    assert techniques == ["T1566", "T1190", "T1133"]


def test_get_techniques_for_category_invalid():
    """Test that an invalid category returns an empty list."""
    techniques = get_techniques_for_category("Unknown Category")
    assert techniques == []


def test_get_technique_name_valid():
    """Test that a valid technique ID returns the expected name."""
    name = get_technique_name("T1566")
    assert name == "Phishing"


def test_get_technique_name_invalid():
    """Test that an invalid technique ID returns the ID itself."""
    name = get_technique_name("T9999")
    assert name == "T9999"
