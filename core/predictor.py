import pickle
import numpy as np
import pandas as pd


class IDSPredictor:
    def __init__(self, model_path: str):
        with open(model_path, 'rb') as f:
            bundle = pickle.load(f)
        self.model   = bundle['model']
        self.le      = bundle['label_encoder']
        self.feature_names = bundle['feature_names']

    def predict(self, X: pd.DataFrame) -> pd.DataFrame:
        """Returns DataFrame with 'prediction' and 'confidence' columns."""
        probs      = self.model.predict_proba(X)
        pred_idx   = np.argmax(probs, axis=1)
        confidence = probs[np.arange(len(probs)), pred_idx]

        return pd.DataFrame({
            'prediction': self.le.inverse_transform(pred_idx),
            'confidence': (confidence * 100).round(2)
        })