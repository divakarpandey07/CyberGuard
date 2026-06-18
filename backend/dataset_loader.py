
import os,logging
import numpy as np,pandas as pd
from typing import Tuple
import config

logger=logging.getLogger("CyberGuard.Dataset")

RAW_COL_MAP={
    " Flow Duration":"flow_duration"," Total Fwd Packets":"total_fwd_packets",
    " Total Backward Packets":"total_backward_packets",
    " Total Length of Fwd Packets":"total_length_fwd_packets",
    " Total Length of Bwd Packets":"total_length_bwd_packets",
    " Fwd Packet Length Max":"fwd_packet_length_max"," Fwd Packet Length Min":"fwd_packet_length_min",
    " Fwd Packet Length Mean":"fwd_packet_length_mean"," Fwd Packet Length Std":"fwd_packet_length_std",
    " Bwd Packet Length Max":"bwd_packet_length_max"," Bwd Packet Length Min":"bwd_packet_length_min",
    " Bwd Packet Length Mean":"bwd_packet_length_mean"," Bwd Packet Length Std":"bwd_packet_length_std",
    "Flow Bytes/s":"flow_bytes_s"," Flow Packets/s":"flow_packets_s",
    " Flow IAT Mean":"flow_iat_mean"," Flow IAT Std":"flow_iat_std",
    " Flow IAT Max":"flow_iat_max"," Flow IAT Min":"flow_iat_min",
    " Fwd IAT Total":"fwd_iat_total"," Fwd IAT Mean":"fwd_iat_mean"," Fwd IAT Std":"fwd_iat_std",
    " Fwd IAT Max":"fwd_iat_max"," Fwd IAT Min":"fwd_iat_min",
    " Bwd IAT Total":"bwd_iat_total"," Bwd IAT Mean":"bwd_iat_mean"," Bwd IAT Std":"bwd_iat_std",
    " Bwd IAT Max":"bwd_iat_max"," Bwd IAT Min":"bwd_iat_min",
    " Fwd PSH Flags":"fwd_psh_flags"," Bwd PSH Flags":"bwd_psh_flags",
    " Fwd URG Flags":"fwd_urg_flags"," Bwd URG Flags":"bwd_urg_flags",
    " Fwd Header Length":"fwd_header_length"," Bwd Header Length":"bwd_header_length",
    " Fwd Packets/s":"fwd_packets_s"," Bwd Packets/s":"bwd_packets_s",
    " Min Packet Length":"min_packet_length"," Max Packet Length":"max_packet_length",
    " Packet Length Mean":"packet_length_mean"," Packet Length Std":"packet_length_std",
    " Packet Length Variance":"packet_length_variance",
    " FIN Flag Count":"fin_flag_count"," SYN Flag Count":"syn_flag_count",
    " RST Flag Count":"rst_flag_count"," PSH Flag Count":"psh_flag_count",
    " ACK Flag Count":"ack_flag_count"," URG Flag Count":"urg_flag_count",
    " CWE Flag Count":"cwe_flag_count"," ECE Flag Count":"ece_flag_count",
    " Down/Up Ratio":"down_up_ratio"," Average Packet Size":"average_packet_size",
    " Avg Fwd Segment Size":"avg_fwd_segment_size"," Avg Bwd Segment Size":"avg_bwd_segment_size",
    " Fwd Header Length.1":"fwd_header_length_1",
    "Fwd Avg Bytes/Bulk":"fwd_avg_bytes_bulk"," Fwd Avg Packets/Bulk":"fwd_avg_packets_bulk",
    " Fwd Avg Bulk Rate":"fwd_avg_bulk_rate"," Bwd Avg Bytes/Bulk":"bwd_avg_bytes_bulk",
    " Bwd Avg Packets/Bulk":"bwd_avg_packets_bulk","Bwd Avg Bulk Rate":"bwd_avg_bulk_rate",
    " Subflow Fwd Packets":"subflow_fwd_packets"," Subflow Fwd Bytes":"subflow_fwd_bytes",
    " Subflow Bwd Packets":"subflow_bwd_packets"," Subflow Bwd Bytes":"subflow_bwd_bytes",
    "Init_Win_bytes_forward":"init_win_bytes_forward"," Init_Win_bytes_backward":"init_win_bytes_backward",
    " act_data_pkt_fwd":"act_data_pkt_fwd"," min_seg_size_forward":"min_seg_size_forward",
    "Active Mean":"active_mean"," Active Std":"active_std"," Active Max":"active_max",
    " Active Min":"active_min","Idle Mean":"idle_mean"," Idle Std":"idle_std",
    " Idle Max":"idle_max"," Idle Min":"idle_min"," Label":"label_raw",
}

def load_cicids2017(max_rows_per_file=None)->pd.DataFrame:
    available=[os.path.join(config.DATASET_DIR,f) for f in config.CICIDS_FILES
               if os.path.exists(os.path.join(config.DATASET_DIR,f))]
    if not available:
        raise FileNotFoundError(
            f"\n\n❌ No CICIDS2017 CSV files found in: {config.DATASET_DIR}\n"
            "  Download: https://www.unb.ca/cic/datasets/ids-2017.html\n"
            "  Or Kaggle: https://www.kaggle.com/datasets/cicdataset/cicids2017\n"
            "  Run: python backend/download_dataset.py\n")
    logger.info("Found %d CICIDS2017 file(s). Loading...",len(available))
    frames=[]
    for path in available:
        try:
            df=pd.read_csv(path,nrows=max_rows_per_file,low_memory=False,
                           encoding="utf-8",encoding_errors="replace")
            frames.append(df);logger.info("  %s: %d rows",os.path.basename(path),len(df))
        except Exception as e:
            logger.warning("Skipping %s: %s",os.path.basename(path),e)
    if not frames: raise RuntimeError("All CSV files failed to load.")
    raw=pd.concat(frames,ignore_index=True)
    logger.info("Total raw rows: %d",len(raw))
    return _clean(raw)

def _clean(raw:pd.DataFrame)->pd.DataFrame:
    col_rename={}
    for col in raw.columns:
        stripped=col.strip()
        if col in RAW_COL_MAP: col_rename[col]=RAW_COL_MAP[col]
        elif " "+stripped in RAW_COL_MAP: col_rename[col]=RAW_COL_MAP[" "+stripped]
        elif stripped in RAW_COL_MAP: col_rename[col]=RAW_COL_MAP[stripped]
        else:
            lower=stripped.lower()
            for rk,ck in RAW_COL_MAP.items():
                if rk.strip().lower()==lower: col_rename[col]=ck; break
    raw=raw.rename(columns=col_rename)
    if "label_raw" not in raw.columns:
        if "Label" in raw.columns: raw=raw.rename(columns={"Label":"label_raw"})
        else: raise ValueError("Label column not found")
    raw["label"]=raw["label_raw"].str.strip().map(config.CICIDS_LABEL_MAP)
    unk=raw["label"].isna()
    if unk.sum()>0:
        logger.warning("%d unmapped labels -> Anomaly",unk.sum())
        raw.loc[unk,"label"]=4
    raw["label"]=raw["label"].astype(int)
    missing=[f for f in config.FEATURE_NAMES if f not in raw.columns]
    for col in missing: raw[col]=0.0
    df=raw[config.FEATURE_NAMES+["label"]].copy()
    df.replace([np.inf,-np.inf],np.nan,inplace=True)
    before=len(df);df.dropna(inplace=True)
    logger.info("Dropped %d NaN/Inf rows. Clean: %d",before-len(df),len(df))
    nn=[c for c in config.FEATURE_NAMES if "min" not in c.lower() and "iat" not in c.lower()]
    for col in nn:
        if df[col].min()<0: df[col]=df[col].clip(lower=0)
    logger.info("Label distribution:\n%s",df["label"].value_counts().to_string())
    return df
