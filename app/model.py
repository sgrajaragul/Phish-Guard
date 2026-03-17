"""
model.py — Trains and serves the phishing classifier.

Algorithm: Random Forest + TF-IDF text features fused with engineered features.
Training data: SpamAssassin public corpus (easy_ham / spam directories).

Usage:
  python train.py          # one-time training, saves models/phish_model.pkl
  from app.model import predict   # inference
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from scipy.sparse import hstack, csr_matrix

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "phish_model.pkl")


# ── Training ──────────────────────────────────────────────────────────────────

def train(emails: list[dict], labels: list[int], save: bool = True) -> dict:
    """
    Train the classifier.

    Args:
        emails: list of parsed email dicts (from parser.py)
        labels: list of ints — 1 = phishing, 0 = legitimate
        save:   persist model to disk

    Returns:
        dict with model objects and evaluation metrics
    """
    from app.features import extract_features, features_to_vector

    print(f"[*] Training on {len(emails)} emails ({sum(labels)} phishing, {len(labels)-sum(labels)} legit)")

    # ── Build feature matrix ──────────────────────────────────
    texts        = []
    eng_vectors  = []
    feature_keys = None

    for parsed in emails:
        feat_result = extract_features(parsed)
        vec, keys = features_to_vector(feat_result["features"])
        eng_vectors.append(vec)
        if feature_keys is None:
            feature_keys = keys
        # Use subject + body as text for TF-IDF
        text = f"{parsed.get('subject','')} {parsed.get('body_plain','')}"
        texts.append(text[:5000])  # cap at 5k chars for speed

    # TF-IDF on raw text
    tfidf = TfidfVectorizer(
        max_features=3000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=2,
    )
    X_tfidf = tfidf.fit_transform(texts)

    # Engineered features
    X_eng = csr_matrix(np.array(eng_vectors, dtype=np.float32))

    # Fuse both feature sets
    X = hstack([X_tfidf, X_eng])
    y = np.array(labels)

    # ── Train / test split ────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── Model ─────────────────────────────────────────────────
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # ── Evaluate ──────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
    cm     = confusion_matrix(y_test, y_pred).tolist()
    print("\n[*] Evaluation Report:\n", report)

    bundle = {
        "clf": clf,
        "tfidf": tfidf,
        "feature_keys": feature_keys,
        "metrics": {"report": report, "confusion_matrix": cm},
    }

    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(bundle, f)
        print(f"[*] Model saved to {MODEL_PATH}")

    return bundle


# ── Inference ─────────────────────────────────────────────────────────────────

_bundle_cache = None

def _load_bundle() -> dict:
    global _bundle_cache
    if _bundle_cache is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                "Model not found. Run `python train.py` first to train the model."
            )
        with open(MODEL_PATH, "rb") as f:
            _bundle_cache = pickle.load(f)
    return _bundle_cache


def predict(parsed: dict) -> dict:
    """
    Predict whether a parsed email is phishing or legitimate.

    Returns:
        {
          "label":       "Phishing" | "Legitimate",
          "confidence":  float (0.0–1.0),
          "probability": {"Phishing": float, "Legitimate": float}
        }
    """
    from app.features import extract_features, features_to_vector

    bundle       = _load_bundle()
    clf          = bundle["clf"]
    tfidf        = bundle["tfidf"]
    feature_keys = bundle["feature_keys"]

    feat_result = extract_features(parsed)
    eng_vec, _ = features_to_vector(feat_result["features"])

    # Align engineered vector to training feature keys
    feat_dict = feat_result["features"]
    aligned   = [float(feat_dict.get(k, 0.0)) for k in feature_keys]

    text = f"{parsed.get('subject','')} {parsed.get('body_plain','')}"
    X_tfidf = tfidf.transform([text[:5000]])
    X_eng   = csr_matrix(np.array([aligned], dtype=np.float32))
    X       = hstack([X_tfidf, X_eng])

    proba = clf.predict_proba(X)[0]   # [P(legit), P(phish)]
    pred  = clf.predict(X)[0]

    return {
        "label":       "Phishing" if pred == 1 else "Legitimate",
        "confidence":  float(max(proba)),
        "probability": {
            "Legitimate": float(proba[0]),
            "Phishing":   float(proba[1]),
        },
    }


def model_exists() -> bool:
    return os.path.exists(MODEL_PATH)
