
import os,sys
ROOT_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR=os.path.join(ROOT_DIR,"dataset")
def print_manual_steps():
    print("""
============================================================
  CyberGuard IDS v4 - CICIDS2017 Dataset Download Guide
============================================================
METHOD 1 - Direct Download (Recommended)
  https://www.unb.ca/cic/datasets/ids-2017.html
  1. Open the link -> Download Dataset -> Register (free)
  2. Download all 8 CSV files (~2.4 GB total)
  3. Place ALL CSV files in: """ + DATASET_DIR + """

METHOD 2 - Kaggle Mirror (Easier)
  https://www.kaggle.com/datasets/cicdataset/cicids2017
  pip install kaggle
  kaggle datasets download -d cicdataset/cicids2017
  unzip cicids2017.zip -d dataset/

Minimum viable (fast testing):
  - Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  - Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  - Monday-WorkingHours.pcap_ISCX.csv

Then run: python backend/train.py
""")
if __name__=="__main__":
    print_manual_steps()
