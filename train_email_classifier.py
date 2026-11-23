import argparse
import os
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_DATASET_DIR = PROJECT_DIR.parent / "archive (1)"
DATASET_FILENAME = "phishing_email.csv"
OUTPUT_PATH = PROJECT_DIR / "email_classifier.joblib"


def load_dataset(dataset_dir: Path) -> tuple[list[str], list[int]]:
    csv_path = dataset_dir / DATASET_FILENAME
    if not csv_path.is_file():
        raise FileNotFoundError(
            f"Could not find {DATASET_FILENAME} in {dataset_dir}. "
            "Pass the folder containing the Kaggle aggregate CSV."
        )

    frame = pd.read_csv(csv_path, usecols=["text_combined", "label"], dtype=str)
    frame = frame.dropna(subset=["text_combined", "label"])
    frame["text_combined"] = frame["text_combined"].str.strip()
    frame = frame[frame["text_combined"] != ""]

    label_values = frame["label"].str.strip().str.lower()
    label_map = {
        "0": 0,
        "legitimate": 0,
        "safe": 0,
        "ham": 0,
        "1": 1,
        "phishing": 1,
        "spam": 1,
        "fraud": 1,
        "malicious": 1,
    }
    labels = label_values.map(label_map)
    if labels.isna().any() or set(labels.unique()) != {0, 1}:
        unknown = sorted(label_values[labels.isna()].unique().tolist())
        raise ValueError(f"Dataset labels must map to legitimate/phishing; unknown labels: {unknown[:10]}")

    return frame["text_combined"].tolist(), labels.astype(int).tolist()


def create_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            ngram_range=(1, 2),
            min_df=2,
            max_features=120_000,
            sublinear_tf=True,
        )),
        ("classifier", LogisticRegression(
            class_weight="balanced",
            max_iter=300,
            random_state=42,
        )),
    ])


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the local email phishing classifier.")
    parser.add_argument(
        "dataset_dir",
        nargs="?",
        type=Path,
        default=DEFAULT_DATASET_DIR,
        help=f"Folder containing {DATASET_FILENAME} (default: {DEFAULT_DATASET_DIR})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help=f"Output model path (default: {OUTPUT_PATH})",
    )
    args = parser.parse_args()

    texts, labels = load_dataset(args.dataset_dir)
    print(f"Loaded {len(texts):,} emails; phishing={sum(labels):,}, legitimate={len(labels) - sum(labels):,}")

    train_texts, test_texts, train_labels, test_labels = train_test_split(
        texts,
        labels,
        test_size=0.15,
        random_state=42,
        stratify=labels,
    )
    evaluation_model = create_pipeline()
    evaluation_model.fit(train_texts, train_labels)
    predictions = evaluation_model.predict(test_texts)
    print("Held-out evaluation (15% stratified split):")
    print(classification_report(
        test_labels,
        predictions,
        labels=[0, 1],
        target_names=["legitimate", "phishing"],
        digits=4,
        zero_division=0,
    ))

    final_model = create_pipeline()
    final_model.fit(texts, labels)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp_path = args.output.with_name(f".{args.output.name}.tmp")
    try:
        joblib.dump(final_model, temp_path, compress=3)
        os.replace(temp_path, args.output)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    print(f"Saved trained model to {args.output}")


if __name__ == "__main__":
    main()
