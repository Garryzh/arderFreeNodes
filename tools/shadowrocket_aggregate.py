#!/usr/bin/env python3
import base64, json, re, urllib.parse, urllib.request
from pathlib import Path
import yaml

SOURCES = [
"https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
"https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml",
"https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
"https://raw.githubusercontent.com/clashv2ray-hub/v2rayfree/refs/heads/main/v2ray.txt",
"https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
"https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/clash.yaml",
"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/clash.yaml",
"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/singbox.json",
"https://raw.githubusercontent.com/yy1588133/proxy-pool/main/clash.yaml",
"https://raw.githubusercontent.com/yy1588133/proxy-pool/main/v2ray.txt",
]
SCHEMES=("vmess://","vless://","trojan://","ss://","ssr://","hysteria://","hysteria2://","hy2://","tuic://")

def q(v): return urllib.parse.quote(str(v), safe="")
def b64s(s): return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
def frag(name): return "#" + q(name or "node")

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0 ShadowrocketAggregator/1.0"})
    with urllib.request.urlopen(req,timeout=25) as r:
        return r.read().decode("utf-8","ignore")

def maybe_b64(text):
    s="".join(text.split())
    if len(s)<32 or re.search(r"[^A-Za-z0-9+/=_-]",s): return None
    try:
        raw=base64.b64decode(s + "="*((4-len(s)%4)%4)).decode("utf-8","ignore")
        return raw if any(x in raw for x in SCHEMES) else None
    except Exception: return None

def direct_links(text):
    out=[]
    decoded=maybe_b64(text)
    if decoded: text+="\n"+decoded
    for line in text.replace("\r","\n").split("\n"):
        line=line.strip()
        if line.startswith(SCHEMES): out.append(line)
    return out

def clash_proxy(p):
    t=str(p.get("type","")).lower(); name=p.get("name",t); host=p.get("server"); port=p.get("port")
    if not host or not port: return None
    if t=="ss":
        method=p.get("cipher"); pwd=p.get("password")
        if method and pwd: return f"ss://{b64s(str(method)+':'+str(pwd))}@{host}:{port}{frag(name)}"
    if t=="trojan":
        pwd=p.get("password"); params={"security":"tls"}
        if p.get("sni"): params["sni"]=p["sni"]
        net=p.get("network")
        if net: params["type"]=net
        if net=="ws":
            if p.get("ws-opts",{}).get("path"): params["path"]=p["ws-opts"]["path"]
            h=p.get("ws-opts",{}).get("headers",{}).get("Host")
            if h: params["host"]=h
        return f"trojan://{q(pwd)}@{host}:{port}?{urllib.parse.urlencode(params)}{frag(name)}" if pwd else None
    if t=="vless":
        uid=p.get("uuid"); params={"encryption":"none"}
        if p.get("tls"): params["security"]="tls"
        if p.get("servername") or p.get("sni"): params["sni"]=p.get("servername") or p.get("sni")
        net=p.get("network")
        if net: params["type"]=net
        if net=="ws":
            w=p.get("ws-opts",{})
            if w.get("path"): params["path"]=w["path"]
            if w.get("headers",{}).get("Host"): params["host"]=w["headers"]["Host"]
        return f"vless://{uid}@{host}:{port}?{urllib.parse.urlencode(params)}{frag(name)}" if uid else None
    if t=="vmess":
        uid=p.get("uuid")
        if not uid: return None
        obj={"v":"2","ps":name,"add":host,"port":str(port),"id":uid,"aid":str(p.get("alterId",0)),"scy":p.get("cipher","auto"),"net":p.get("network","tcp"),"type":"none","host":"","path":"","tls":"tls" if p.get("tls") else "","sni":p.get("servername") or p.get("sni","")}
        w=p.get("ws-opts",{})
        if obj["net"]=="ws":
            obj["path"]=w.get("path",""); obj["host"]=w.get("headers",{}).get("Host","")
        return "vmess://"+base64.b64encode(json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if t in ("hysteria2","hy2"):
        pwd=p.get("password"); params={}
        if p.get("sni"): params["sni"]=p["sni"]
        if p.get("skip-cert-verify"): params["insecure"]="1"
        qs=("?"+urllib.parse.urlencode(params)) if params else ""
        return f"hysteria2://{q(pwd)}@{host}:{port}{qs}{frag(name)}" if pwd else None
    if t=="tuic":
        uid=p.get("uuid"); pwd=p.get("password"); params={}
        if p.get("sni"): params["sni"]=p["sni"]
        return f"tuic://{q(uid)}:{q(pwd)}@{host}:{port}?{urllib.parse.urlencode(params)}{frag(name)}" if uid and pwd else None
    return None

def parse_clash(text):
    try:
        d=yaml.safe_load(text)
        if not isinstance(d,dict) or not isinstance(d.get("proxies"),list): return []
        return [x for x in (clash_proxy(p) for p in d["proxies"]) if x]
    except Exception: return []

def singbox_outbound(o):
    t=str(o.get("type","")).lower(); name=o.get("tag",t); host=o.get("server"); port=o.get("server_port")
    if not host or not port: return None
    if t=="shadowsocks":
        method=o.get("method"); pwd=o.get("password")
        return f"ss://{b64s(str(method)+':'+str(pwd))}@{host}:{port}{frag(name)}" if method and pwd else None
    if t=="trojan":
        pwd=o.get("password"); tls=o.get("tls",{}); params={"security":"tls"}
        if tls.get("server_name"): params["sni"]=tls["server_name"]
        return f"trojan://{q(pwd)}@{host}:{port}?{urllib.parse.urlencode(params)}{frag(name)}" if pwd else None
    if t=="vless":
        uid=o.get("uuid"); tls=o.get("tls",{}); tr=o.get("transport",{}); params={"encryption":"none"}
        if tls.get("enabled"): params["security"]="tls"
        if tls.get("server_name"): params["sni"]=tls["server_name"]
        if tr.get("type"): params["type"]=tr["type"]
        if tr.get("path"): params["path"]=tr["path"]
        if tr.get("headers",{}).get("Host"): params["host"]=tr["headers"]["Host"]
        return f"vless://{uid}@{host}:{port}?{urllib.parse.urlencode(params)}{frag(name)}" if uid else None
    if t=="vmess":
        uid=o.get("uuid"); tr=o.get("transport",{}); tls=o.get("tls",{})
        if not uid: return None
        obj={"v":"2","ps":name,"add":host,"port":str(port),"id":uid,"aid":str(o.get("alter_id",0)),"scy":o.get("security","auto"),"net":tr.get("type","tcp"),"type":"none","host":tr.get("headers",{}).get("Host",""),"path":tr.get("path",""),"tls":"tls" if tls.get("enabled") else "","sni":tls.get("server_name","")}
        return "vmess://"+base64.b64encode(json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if t=="hysteria2":
        pwd=o.get("password"); tls=o.get("tls",{}); params={}
        if tls.get("server_name"): params["sni"]=tls["server_name"]
        if tls.get("insecure"): params["insecure"]="1"
        qs=("?"+urllib.parse.urlencode(params)) if params else ""
        return f"hysteria2://{q(pwd)}@{host}:{port}{qs}{frag(name)}" if pwd else None
    if t=="tuic":
        uid=o.get("uuid"); pwd=o.get("password"); tls=o.get("tls",{}); params={}
        if tls.get("server_name"): params["sni"]=tls["server_name"]
        return f"tuic://{q(uid)}:{q(pwd)}@{host}:{port}?{urllib.parse.urlencode(params)}{frag(name)}" if uid and pwd else None
    return None

def parse_singbox(text):
    try:
        d=json.loads(text)
        return [x for x in (singbox_outbound(o) for o in d.get("outbounds",[])) if x]
    except Exception: return []

def key(u): return u.split("#",1)[0]
def main():
    found=[]; report=[]
    for url in SOURCES:
        try:
            text=fetch(url)
            items=direct_links(text)+parse_clash(text)+parse_singbox(text)
            report.append({"url":url,"ok":True,"count":len(items)})
            found.extend(items)
        except Exception as e:
            report.append({"url":url,"ok":False,"error":str(e)[:160],"count":0})
    uniq=[]; seen=set()
    for u in found:
        k=key(u)
        if k not in seen:
            seen.add(k); uniq.append(u)
    Path("shadowrocket").mkdir(exist_ok=True)
    plain="\n".join(uniq)+"\n"
    encoded=base64.b64encode(plain.encode()).decode()
    Path("shadowrocket/sub.txt").write_text(encoded,encoding="utf-8")
    Path("shadowrocket/plain.txt").write_text(plain,encoding="utf-8")
    Path("shadowrocket/status.json").write_text(json.dumps({"total":len(uniq),"sources":report},ensure_ascii=False,indent=2),encoding="utf-8")
    print(f"generated {len(uniq)} unique nodes from {len(SOURCES)} sources")
if __name__=="__main__": main()
