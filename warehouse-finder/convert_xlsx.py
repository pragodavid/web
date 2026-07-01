"""
Převod skladového katalogu z XLS/XLSX do katalog.json pro Warehouse Finder.

Použití:
    python3 convert_xlsx.py vstup.xlsx katalog.json

Očekávaná struktura sloupců (v tomto pořadí, bez ohledu na názvy hlaviček):
    1. kod        - kód položky (text)
    2. popis      - úplný popis položky (text)
    3. zasoby     - skladové množství (číslo)

Skript:
  - automaticky rozpozná a přeskočí případný řádek s hlavičkou,
  - ořeže přebytečné mezery v textových polích,
  - zkontroluje duplicitní kódy a neplatné/zásoby mimo číselný formát,
  - chybějící/neplatné zásoby nastaví na 0 a upozorní na ně,
  - výsledek uloží jako pole objektů {kod, popis, zasoby}.
"""

import sys
import json
import pandas as pd

COLUMNS = ["kod", "popis", "zasoby"]


def convert(xlsx_path: str) -> tuple[list[dict], list[str]]:
    raw = pd.read_excel(xlsx_path, header=None)

    if raw.shape[1] < len(COLUMNS):
        raise ValueError(
            f"Soubor má jen {raw.shape[1]} sloupců, očekáváno alespoň {len(COLUMNS)} "
            f"({', '.join(COLUMNS)})."
        )

    # Pokud první řádek vypadá jako hlavička (sloupec "zasoby" není číslo), přeskočíme ho
    first_val = raw.iloc[0, 2]
    if not isinstance(first_val, (int, float)) or pd.isna(first_val):
        try:
            float(str(first_val).replace(",", "."))
            is_header = False
        except ValueError:
            is_header = True
        if is_header:
            raw = raw.iloc[1:].reset_index(drop=True)

    df = raw.iloc[:, : len(COLUMNS)].copy()
    df.columns = COLUMNS

    for col in ["kod", "popis"]:
        df[col] = df[col].fillna("").astype(str).str.strip()
        df[col] = df[col].replace("nan", "")

    df["zasoby"] = pd.to_numeric(
        df["zasoby"].astype(str).str.replace(",", ".").str.strip(), errors="coerce"
    )

    warnings = []

    empty_kod = df["kod"].eq("").sum()
    if empty_kod:
        warnings.append(f"{empty_kod} řádek/ů má prázdný kód položky.")

    dup_mask = df["kod"].duplicated(keep=False) & df["kod"].ne("")
    if dup_mask.any():
        dups = sorted(set(df.loc[dup_mask, "kod"]))
        warnings.append(f"Duplicitní kódy ({len(dups)}): {', '.join(dups[:20])}" +
                         (" …" if len(dups) > 20 else ""))

    invalid_stock = df["zasoby"].isna()
    if invalid_stock.any():
        bad = df.loc[invalid_stock, "kod"].tolist()
        warnings.append(
            f"{invalid_stock.sum()} řádek/ů má neplatné zásoby (nastaveno na 0): "
            + ", ".join(bad[:20]) + (" …" if len(bad) > 20 else "")
        )

    df["zasoby"] = df["zasoby"].fillna(0).astype(int)

    # odstranit zcela prázdné řádky (žádný kód ani popis)
    before = len(df)
    df = df[~((df["kod"] == "") & (df["popis"] == ""))]
    removed = before - len(df)
    if removed:
        warnings.append(f"Odstraněno {removed} zcela prázdných řádků.")

    items = df.to_dict(orient="records")
    return items, warnings


def main():
    if len(sys.argv) != 3:
        print("Použití: python3 convert_xlsx.py vstup.xlsx katalog.json")
        sys.exit(1)

    xlsx_path, json_path = sys.argv[1], sys.argv[2]
    items, warnings = convert(xlsx_path)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)

    print(f"Hotovo: {len(items)} položek zapsáno do {json_path}")
    if warnings:
        print("\nUpozornění:")
        for w in warnings:
            print(f"  - {w}")


if __name__ == "__main__":
    main()
