def clean_input(ecosystem: str):
    clean_ecosystem = ecosystem.strip().upper()

    if not clean_ecosystem:
        raise ValueError("Ecosystem cannot be empty")

    return clean_ecosystem
