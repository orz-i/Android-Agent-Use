#!/usr/bin/env python3
"""Provision the optional NER assets from an extracted aiunit package.

The model is OPPO's `engine-nlp_ner_information_intent` blob: not ours to redistribute,
so it is never committed. Point this at the directory holding `model.tflite`,
`token2id.txt` and `label2id.txt` (see apk_analysis/aiunit-剖析与AAU接入.md) and it
validates the three files and copies them under AAU's own asset names.

    python aau-ner/tools/import_ner_assets.py --source /path/to/x_ner

Validation is strict on purpose: a silent vocabulary or label change would turn every
extracted span into garbage, so a mismatch here is a hard error instead.
"""

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

ASSETS = Path(__file__).resolve().parents[1] / "src" / "main" / "assets"
NAME = "aau_ner_v1"

# Every suffix the 3.0.6 label table uses. A new suffix is not fatal at runtime
# (it degrades to EntityType.Other), but it should be a deliberate decision here.
SUFFIXES = {
    "NAME", "PHONE", "STANDARD_ADDRESS", "ORAL_STANDARD_ADDRESS", "ORAL_WIDE_ADDRESS",
    "ADMINISTRATIVE_DIVISION", "COMPANY", "OTHER_ORGANIZATION", "GOVERNMENT_ORGANIZATION",
    "SCHOOL", "HEALTHCARE", "RESTAURANT", "HOTEL", "SUPERMARKET", "ENTERTAINMENT",
    "SPOT", "OFFICE_BUILDING", "BANK_NAME", "BANK_ID", "EXPRESS_NUMBER", "FLIGHT_NUMBER",
    "TRAIN_NUMBER", "SUBWAY_STATION", "BUS_STATION", "AIRPORT_TRAIN", "OIL_ELECTRIC",
    "OTHER_ADDRESS",
}


def parse(path):
    table = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.rsplit(None, 1)
        if len(parts) != 2:
            raise SystemExit(f"{path.name}:{number}: expected '<token> <id>'")
        token, raw = parts
        try:
            table[token] = int(raw)
        except ValueError:
            raise SystemExit(f"{path.name}:{number}: '{raw}' is not an id")
    return table


def check_vocab(path, vocab):
    missing = [token for token in ("[PAD]", "[UNK]", "[SPACE]") if token not in vocab]
    if missing:
        raise SystemExit(f"{path.name}: missing {', '.join(missing)}")
    if vocab["[PAD]"] != 0:
        raise SystemExit(f"{path.name}: [PAD] must be 0, found {vocab['[PAD]']}")
    wide = [token for token in vocab if len(token) > 1 and not token.startswith("[")]
    if wide:
        raise SystemExit(f"{path.name}: multi-character tokens are not supported: {wide[:5]}")
    if len(set(vocab.values())) != len(vocab):
        raise SystemExit(f"{path.name}: duplicate ids")
    return len(vocab)


def check_labels(path, labels):
    if labels.get("[PAD]") != 0:
        raise SystemExit(f"{path.name}: [PAD] must be 0")
    ids = sorted(labels.values())
    if ids != list(range(len(ids))):
        raise SystemExit(f"{path.name}: label ids are not contiguous from 0")
    for token in labels:
        if token in ("[PAD]", "O"):
            continue
        prefix, dash, suffix = token.partition("-")
        if not dash or prefix not in "BIES":
            raise SystemExit(f"{path.name}: '{token}' is not a BIOES tag")
        if suffix not in SUFFIXES:
            raise SystemExit(f"{path.name}: unknown entity class '{suffix}' (update SUFFIXES and Labels)")
    return len(labels)


def check_model(path):
    # Flatbuffer: 4-byte root offset, then the "TFL3" file identifier.
    if path.read_bytes()[:8][4:] != b"TFL3":
        raise SystemExit(f"{path.name}: not a TFLite flatbuffer")
    return path.stat().st_size


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, type=Path, help="directory with model.tflite, token2id.txt, label2id.txt")
    parser.add_argument("--out", type=Path, default=ASSETS, help=f"asset directory (default: {ASSETS})")
    args = parser.parse_args()

    model = args.source / "model.tflite"
    for path in (model, args.source / "token2id.txt", args.source / "label2id.txt"):
        if not path.is_file():
            raise SystemExit(f"missing {path}")

    vocab_size = check_vocab(args.source / "token2id.txt", parse(args.source / "token2id.txt"))
    label_size = check_labels(args.source / "label2id.txt", parse(args.source / "label2id.txt"))
    model_size = check_model(model)

    args.out.mkdir(parents=True, exist_ok=True)
    for source, target in (
        (model, f"{NAME}.tflite"),
        (args.source / "token2id.txt", f"{NAME}.vocab"),
        (args.source / "label2id.txt", f"{NAME}.labels"),
    ):
        destination = args.out / target
        shutil.copyfile(source, destination)
        print(f"{destination}  {destination.stat().st_size:>9,} bytes  sha256:{digest(destination)}")

    print(f"\nvocabulary {vocab_size} tokens, {label_size} labels, model {model_size:,} bytes")
    if not (args.out / f"{NAME}.tflite").is_file():
        sys.exit("asset copy failed")


if __name__ == "__main__":
    main()
