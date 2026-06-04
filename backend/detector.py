import os,logging,numpy as np,joblib
from typing import Dict,Optional,List
import config
logger=logging.getLogger("CyberGuard.Detector")
class EnsembleDetector:
    def __init__(self):
        self.xgb_model=None;self.iso_model=None;self.scaler=None
        self._loaded=False;self._metadata={}
    def load_models(self)->bool:
        try:
            xp=os.path.join(config.MODEL_DIR,"xgb_model.pkl")
            ip=os.path.join(config.MODEL_DIR,"iso_forest.pkl")
            sp=os.path.join(config.MODEL_DIR,"scaler.pkl")
            mp=os.path.join(config.MODEL_DIR,"metadata.json")
            if not all(os.path.exists(p) for p in [xp,ip,sp]):
                logger.warning("Model files missing. Run train.py first.")
                return False
            self.xgb_model=joblib.load(xp);self.iso_model=joblib.load(ip)
            self.scaler=joblib.load(sp)
            if os.path.exists(mp):
                import json
                with open(mp) as f: self._metadata=json.load(f)
                logger.info("Models loaded | CV Accuracy: %.2f%%",
                            self._metadata.get("cv_accuracy_mean",0)*100)
            self._loaded=True;return True
        except Exception as e:
            logger.error("Model load failed: %s",e);return False
    @property
    def is_ready(self)->bool: return self._loaded
    @property
    def metadata(self)->dict: return self._metadata
    def predict(self,fd:dict)->dict:
        if not self._loaded: return self._unavailable()
        X=self._to_array(fd)
        xp=self.xgb_model.predict_proba(X)[0]
        xc=int(np.argmax(xp));xconf=float(xp[xc])
        iso_s=float(self.iso_model.score_samples(X)[0])
        iso_np=float(np.clip((iso_s+0.7)/0.8,0,1))
        fc,fconf=xc,xconf
        if xc==0 and iso_np<0.30 and getattr(config, "ANOMALY_DETECTION_ENABLED", True):
            fc=4;fconf=config.ENSEMBLE_W_XGB*xconf+config.ENSEMBLE_W_ISO*(1-iso_np)
        elif xc!=0:
            fconf=float(np.clip(config.ENSEMBLE_W_XGB*xconf+config.ENSEMBLE_W_ISO*(1-iso_np),0,1))
        if fconf<config.CONFIDENCE_THRESHOLD and fc!=0: fc=4
        label=config.ATTACK_LABELS.get(fc,"Unknown")
        scores={config.ATTACK_LABELS.get(i,f"C{i}"):round(float(p),4)
                for i,p in enumerate(xp) if i in config.ATTACK_LABELS}
        scores["Anomaly(IF)"]=round(1-iso_np,4)
        return {"label":label,"label_id":fc,"confidence":round(fconf,3),
                "is_attack":(fc!=0),"scores":scores}
    def _to_array(self,fd):
        vals=[fd.get(n,0.0) for n in config.FEATURE_NAMES]
        X=np.array(vals,dtype=np.float32).reshape(1,-1)
        return self.scaler.transform(X)
    @staticmethod
    def _unavailable():
        return {"label":"Model Not Loaded","label_id":-1,"confidence":0.0,"is_attack":False,"scores":{}}
