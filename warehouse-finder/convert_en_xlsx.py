"""
Převod exportu anglických popisů do popis_en.json pro Warehouse Finder.

Použití:
    python3 convert_en_xlsx.py vstup.xlsx popis_en.json katalog.json

Očekávaná struktura sloupců (bez ohledu na názvy hlaviček):
    1. kod   - kód položky (text)
    2-4. tři sloupce anglického popisu (text), které se sloučí do jednoho
         textu oddělovačem " — ", prázdné buňky se vynechají

Pravidla:
  - řádky, kde "kod" začíná podtržítkem ("_..."), se ignorují (nejedná se
    o platné kódy v tomto exportu),
  - zbylé kódy se porovnají s katalog.json (soubor 1) — pokud kód v katalogu
    neexistuje (uzavřená/neplatná položka), řádek se přeskočí,
  - výsledek je slovník {kod: anglický_popis}, uložený do popis_en.json.
"""

import sys
import json
import pandas as pd

EN_SEP = " — "
HEADER_HINTS = {"kod", "kód", "code", "item", "číslo", "code/sku"}


def load_catalog_codes(katalog_path: str) -> set[str]:
    with open(katalog_path, "r", encoding="utf-8") as f:
        katalog = json.load(f)
    return {item["kod"] for item in katalog}


def convert(xlsx_path: str, katalog_path: str) -> tuple[dict, dict]:
    raw = pd.read_excel(xlsx_path, header=None)

    if raw.shape[1] < 4:
        raise ValueError(
            f"Soubor má jen {raw.shape[1]} sloupců, očekáváno alespoň 4 "
            f"(kod + 3 sloupce anglického popisu)."
        )

    raw = raw.iloc[:, :4].copy()
    raw.columns = ["kod", "en1", "en2", "en3"]

    for col in raw.columns:
        raw[col] = raw[col].fillna("").astype(str).str.strip()
        raw[col] = raw[col].replace("nan", "")

    # přeskočit případnou hlavičku
    first_kod = raw.iloc[0]["kod"].strip().lower()
    if first_kod in HEADER_HINTS:
        raw = raw.iloc[1:].reset_index(drop=True)

    catalog_codes = load_catalog_codes(katalog_path)

    stats = {
        "total_rows": len(raw),
        "saved": 0,
        "skipped_underscore": 0,
        "skipped_not_in_catalog": 0,
        "skipped_empty": 0,
    }

    result = {}
    for _, row in raw.iterrows():
        kod = row["kod"].strip()

        if not kod:
            stats["skipped_empty"] += 1
            continue

        if kod.startswith("_"):
            stats["skipped_underscore"] += 1
            continue

        if kod not in catalog_codes:
            stats["skipped_not_in_catalog"] += 1
            continue

        parts = [row["en1"], row["en2"], row["en3"]]
        merged = EN_SEP.join(p for p in parts if p)

        if not merged:
            stats["skipped_empty"] += 1
            continue

        result[kod] = merged
        stats["saved"] += 1

    return result, stats


def refilter(popis_en_path: str, katalog_path: str) -> int:
    """Odstraní z popis_en.json záznamy, jejichž kód už není v katalog.json.
    Vrací počet odstraněných záznamů."""
    catalog_codes = load_catalog_codes(katalog_path)

    try:
        with open(popis_en_path, "r", encoding="utf-8") as f:
            popis_en = json.load(f)
    except FileNotFoundError:
        return 0

    filtered = {k: v for k, v in popis_en.items() if k in catalog_codes}
    removed = len(popis_en) - len(filtered)

    if removed:
        with open(popis_en_path, "w", encoding="utf-8") as f:
            json.dump(filtered, f, ensure_ascii=False, indent=2)

    return removed


def main():
    if len(sys.argv) != 4:
        print("Použití: python3 convert_en_xlsx.py vstup.xlsx popis_en.json katalog.json")
        sys.exit(1)

    xlsx_path, json_path, katalog_path = sys.argv[1], sys.argv[2], sys.argv[3]
    result, stats = convert(xlsx_path, katalog_path)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"Hotovo: {stats['saved']} anglických popisů zapsáno do {json_path}")
    print(f"  - celkem řádků v souboru: {stats['total_rows']}")
    print(f"  - ignorováno (kód začíná '_'): {stats['skipped_underscore']}")
    print(f"  - přeskočeno (kód není v katalogu): {stats['skipped_not_in_catalog']}")
    print(f"  - přeskočeno (prázdný kód/popis): {stats['skipped_empty']}")


if __name__ == "__main__":
    main()
