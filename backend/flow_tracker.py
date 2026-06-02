
import math,time,threading
from collections import defaultdict
from dataclasses import dataclass,field
from typing import Dict,List,Optional,Tuple
import config

FlowKey=Tuple[str,str,int,int,int]
def _safe_div(a,b,d=0.0): return a/b if b!=0 else d
def _mean(l): return sum(l)/len(l) if l else 0.0
def _std(l):
    if len(l)<2: return 0.0
    m=_mean(l); return math.sqrt(sum((x-m)**2 for x in l)/len(l))
def _iat(ts):
    if len(ts)<2: return [0.0]
    s=sorted(ts); return [s[i+1]-s[i] for i in range(len(s)-1)]

@dataclass
class FlowRecord:
    src_ip:str; dst_ip:str; src_port:int; dst_port:int; protocol:int
    start_time:float=0.0; last_seen:float=0.0
    fwd_lengths:List[int]=field(default_factory=list)
    fwd_timestamps:List[float]=field(default_factory=list)
    fwd_header_len:int=0
    bwd_lengths:List[int]=field(default_factory=list)
    bwd_timestamps:List[float]=field(default_factory=list)
    bwd_header_len:int=0
    fin_flags:int=0;syn_flags:int=0;rst_flags:int=0
    psh_flags_fwd:int=0;psh_flags_bwd:int=0;ack_flags:int=0
    urg_flags_fwd:int=0;urg_flags_bwd:int=0;cwe_flags:int=0;ece_flags:int=0
    init_win_fwd:int=-1;init_win_bwd:int=-1
    active_start:float=0.0;last_active:float=0.0
    active_times:List[float]=field(default_factory=list)
    idle_times:List[float]=field(default_factory=list)
    ACTIVE_TIMEOUT:float=0.5;finished:bool=False

class FlowTracker:
    def __init__(self):
        self._flows:Dict[FlowKey,FlowRecord]={}
        self._completed:List[FlowRecord]=[]
        self._lock=threading.Lock();self._running=True
        threading.Thread(target=self._expire_loop,daemon=True).start()

    def add_packet(self,pkt:dict)->None:
        si=pkt.get("src_ip","0.0.0.0");di=pkt.get("dst_ip","0.0.0.0")
        sp=pkt.get("src_port",0);dp=pkt.get("dst_port",0)
        pr=pkt.get("protocol",0);ln=pkt.get("length",0)
        ts=pkt.get("timestamp",time.time());flags=pkt.get("tcp_flags",{})
        hl=pkt.get("header_length",20);ws=pkt.get("window_size",-1)
        fk=(si,di,sp,dp,pr);bk=(di,si,dp,sp,pr)
        with self._lock:
            if fk in self._flows: key,is_fwd=fk,True
            elif bk in self._flows: key,is_fwd=bk,False
            else:
                key,is_fwd=fk,True
                self._flows[key]=FlowRecord(src_ip=si,dst_ip=di,src_port=sp,dst_port=dp,
                    protocol=pr,start_time=ts,last_seen=ts,active_start=ts,last_active=ts)
            f=self._flows[key]
            gap=ts-f.last_active
            if gap>f.ACTIVE_TIMEOUT and f.last_active>0:
                f.idle_times.append(gap)
                if f.active_start>0: f.active_times.append(f.last_active-f.active_start)
                f.active_start=ts
            f.last_active=ts;f.last_seen=ts
            if is_fwd:
                f.fwd_lengths.append(ln);f.fwd_timestamps.append(ts)
                f.fwd_header_len+=hl;f.psh_flags_fwd+=int(flags.get("P",False))
                f.urg_flags_fwd+=int(flags.get("U",False))
                if f.init_win_fwd==-1 and ws>=0: f.init_win_fwd=ws
            else:
                f.bwd_lengths.append(ln);f.bwd_timestamps.append(ts)
                f.bwd_header_len+=hl;f.psh_flags_bwd+=int(flags.get("P",False))
                f.urg_flags_bwd+=int(flags.get("U",False))
                if f.init_win_bwd==-1 and ws>=0: f.init_win_bwd=ws
            f.fin_flags+=int(flags.get("F",False));f.syn_flags+=int(flags.get("S",False))
            f.rst_flags+=int(flags.get("R",False));f.ack_flags+=int(flags.get("A",False))
            f.cwe_flags+=int(flags.get("C",False));f.ece_flags+=int(flags.get("E",False))
            if flags.get("R") or flags.get("F"): f.finished=True; self._export(key)

    def get_completed_flows(self)->List[dict]:
        with self._lock:
            r=[self._to_features(f) for f in self._completed]
            self._completed.clear()
        return r

    def stop(self): self._running=False

    def _export(self,key):
        f=self._flows.pop(key,None)
        if f and (f.fwd_lengths or f.bwd_lengths): self._completed.append(f)

    def _expire_loop(self):
        while self._running:
            now=time.time()
            with self._lock:
                for k in [k for k,f in self._flows.items() if (now-f.last_seen)>config.FLOW_TIMEOUT]:
                    self._export(k)
            time.sleep(5)

    @staticmethod
    def _to_features(f:FlowRecord)->dict:
        du=max((f.last_seen-f.start_time)*1e6,1);ds=du/1e6
        al=f.fwd_lengths+f.bwd_lengths
        nf=len(f.fwd_lengths);nb=len(f.bwd_lengths);nt=nf+nb
        tbf=sum(f.fwd_lengths);tbb=sum(f.bwd_lengths);tb=tbf+tbb
        fi=_iat(f.fwd_timestamps);bi=_iat(f.bwd_timestamps)
        ats=sorted(f.fwd_timestamps+f.bwd_timestamps);fli=_iat(ats)
        act=f.active_times if f.active_times else [0.0]
        idl=f.idle_times if f.idle_times else [0.0]
        feat={
            "flow_duration":round(du,2),"total_fwd_packets":nf,"total_backward_packets":nb,
            "total_length_fwd_packets":tbf,"total_length_bwd_packets":tbb,
            "fwd_packet_length_max":max(f.fwd_lengths,default=0),
            "fwd_packet_length_min":min(f.fwd_lengths,default=0),
            "fwd_packet_length_mean":round(_mean(f.fwd_lengths),4),
            "fwd_packet_length_std":round(_std(f.fwd_lengths),4),
            "bwd_packet_length_max":max(f.bwd_lengths,default=0),
            "bwd_packet_length_min":min(f.bwd_lengths,default=0),
            "bwd_packet_length_mean":round(_mean(f.bwd_lengths),4),
            "bwd_packet_length_std":round(_std(f.bwd_lengths),4),
            "flow_bytes_s":round(_safe_div(tb,ds),4),
            "flow_packets_s":round(_safe_div(nt,ds),4),
            "flow_iat_mean":round(_mean(fli),4),"flow_iat_std":round(_std(fli),4),
            "flow_iat_max":max(fli,default=0),"flow_iat_min":min(fli,default=0),
            "fwd_iat_total":round(sum(fi),4),"fwd_iat_mean":round(_mean(fi),4),
            "fwd_iat_std":round(_std(fi),4),"fwd_iat_max":max(fi,default=0),
            "fwd_iat_min":min(fi,default=0),"bwd_iat_total":round(sum(bi),4),
            "bwd_iat_mean":round(_mean(bi),4),"bwd_iat_std":round(_std(bi),4),
            "bwd_iat_max":max(bi,default=0),"bwd_iat_min":min(bi,default=0),
            "fwd_psh_flags":f.psh_flags_fwd,"bwd_psh_flags":f.psh_flags_bwd,
            "fwd_urg_flags":f.urg_flags_fwd,"bwd_urg_flags":f.urg_flags_bwd,
            "fwd_header_length":f.fwd_header_len,"bwd_header_length":f.bwd_header_len,
            "fwd_packets_s":round(_safe_div(nf,ds),4),"bwd_packets_s":round(_safe_div(nb,ds),4),
            "min_packet_length":min(al,default=0),"max_packet_length":max(al,default=0),
            "packet_length_mean":round(_mean(al),4),"packet_length_std":round(_std(al),4),
            "packet_length_variance":round(_std(al)**2,4),
            "fin_flag_count":f.fin_flags,"syn_flag_count":f.syn_flags,"rst_flag_count":f.rst_flags,
            "psh_flag_count":f.psh_flags_fwd+f.psh_flags_bwd,"ack_flag_count":f.ack_flags,
            "urg_flag_count":f.urg_flags_fwd+f.urg_flags_bwd,"cwe_flag_count":f.cwe_flags,
            "ece_flag_count":f.ece_flags,"down_up_ratio":round(_safe_div(nb,nf),4),
            "average_packet_size":round(_mean(al),4),
            "avg_fwd_segment_size":round(_mean(f.fwd_lengths),4),
            "avg_bwd_segment_size":round(_mean(f.bwd_lengths),4),
            "fwd_header_length_1":f.fwd_header_len,
            "fwd_avg_bytes_bulk":round(_safe_div(tbf,max(nf,1)),4),
            "fwd_avg_packets_bulk":nf,"fwd_avg_bulk_rate":round(_safe_div(tbf,ds),4),
            "bwd_avg_bytes_bulk":round(_safe_div(tbb,max(nb,1)),4),
            "bwd_avg_packets_bulk":nb,"bwd_avg_bulk_rate":round(_safe_div(tbb,ds),4),
            "subflow_fwd_packets":nf,"subflow_fwd_bytes":tbf,
            "subflow_bwd_packets":nb,"subflow_bwd_bytes":tbb,
            "init_win_bytes_forward":max(f.init_win_fwd,0),
            "init_win_bytes_backward":max(f.init_win_bwd,0),
            "act_data_pkt_fwd":sum(1 for l in f.fwd_lengths if l>0),
            "min_seg_size_forward":min(f.fwd_lengths,default=0),
            "active_mean":round(_mean(act)*1e6,4),"active_std":round(_std(act)*1e6,4),
            "active_max":round(max(act)*1e6,4),"active_min":round(min(act)*1e6,4),
            "idle_mean":round(_mean(idl)*1e6,4),"idle_std":round(_std(idl)*1e6,4),
            "idle_max":round(max(idl)*1e6,4),"idle_min":round(min(idl)*1e6,4),
            "_src_ip":f.src_ip,"_dst_ip":f.dst_ip,"_src_port":f.src_port,
            "_dst_port":f.dst_port,"_protocol":f.protocol,"_timestamp":f.last_seen,
        }
        return feat
