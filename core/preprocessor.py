import pandas as pd
import numpy as np

EXPECTED_FEATURES = [
    'destination port', 'flow duration', 'total fwd packets',
    'total backward packets', 'total length of fwd packets',
    'total length of bwd packets', 'fwd packet length max',
    'fwd packet length min', 'fwd packet length mean',
    'fwd packet length std', 'bwd packet length max',
    'bwd packet length min', 'bwd packet length mean',
    'bwd packet length std', 'flow bytes/s', 'flow packets/s',
    'flow iat mean', 'flow iat std', 'flow iat max', 'flow iat min',
    'fwd iat total', 'fwd iat mean', 'fwd iat std', 'fwd iat max',
    'fwd iat min', 'bwd iat total', 'bwd iat mean', 'bwd iat std',
    'bwd iat max', 'bwd iat min', 'fwd psh flags', 'bwd psh flags',
    'fwd urg flags', 'bwd urg flags', 'fwd header length',
    'bwd header length', 'fwd packets/s', 'bwd packets/s',
    'min packet length', 'max packet length', 'packet length mean',
    'packet length std', 'packet length variance', 'fin flag count',
    'syn flag count', 'rst flag count', 'psh flag count', 'ack flag count',
    'urg flag count', 'cwe flag count', 'ece flag count', 'down/up ratio',
    'average packet size', 'avg fwd segment size', 'avg bwd segment size',
    'fwd header length.1', 'fwd avg bytes/bulk', 'fwd avg packets/bulk',
    'fwd avg bulk rate', 'bwd avg bytes/bulk', 'bwd avg packets/bulk',
    'bwd avg bulk rate', 'subflow fwd packets', 'subflow fwd bytes',
    'subflow bwd packets', 'subflow bwd bytes', 'init_win_bytes_forward',
    'init_win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'active mean', 'active std', 'active max', 'active min',
    'idle mean', 'idle std', 'idle max', 'idle min'
]


def load_and_clean(filepath: str):
    """
    Load a CICFlowMeter CSV, extract timestamp if present,
    return (feature_df, timestamp_series | None).
    Raises ValueError with a human-readable message if columns are missing.
    """
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip().str.lower()

    # grab timestamp before dropping anything
    timestamp = None
    if 'timestamp' in df.columns:
        timestamp = pd.to_datetime(df['timestamp'], errors='coerce')

    # drop non-feature columns
    for col in ['timestamp', 'flow id', 'src ip', 'dst ip', 'src port', 'label']:
        df.drop(columns=[col], inplace=True, errors='ignore')

    # validate required features
    missing = [c for c in EXPECTED_FEATURES if c not in df.columns]
    if missing:
        raise ValueError(
            f"CSV is missing {len(missing)} required columns:\n" +
            ", ".join(missing[:10]) +
            ("..." if len(missing) > 10 else "")
        )

    X = df[EXPECTED_FEATURES].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    return X, timestamp