"""Fresh-process client; reads only an ephemeral synthetic fixture."""
import socket,sys

def install():
    def audit(event,args):
        if event in ("socket.bind","socket.connect") and args[0].family in (socket.AF_INET,socket.AF_INET6):
            if args[1][0] not in ("127.0.0.1","::1"):raise RuntimeError("NON_LOOPBACK_BLOCKED")
        if event=="subprocess.Popen":raise RuntimeError("SUBPROCESS_BLOCKED")
    sys.addaudithook(audit)
install()

import json,pathlib,re,sys,time
from security.hydra_live_client import HydraLiveNodeClient
p=json.loads(pathlib.Path(sys.argv[1]).read_text())
time.time=lambda:p["now"]
try:
    if p.get("pause_before_node"):
        from security import hydra_live_client
        original=hydra_live_client.open_hydra_transport
        def paused(*args,**kwargs):
            pathlib.Path(p["pause_before_node"]).write_text("RESERVED")
            while True:time.sleep(.1)
        hydra_live_client.open_hydra_transport=paused
    if p.get("client_kind")=="remote":
        from security.hydra_nodes import RemoteHydraNode
        result=RemoteHydraNode(p["url"],"node-3",timeout_seconds=p.get("timeout",2)).evaluate("a"*64,"policy-v1",context=p["context"])
        assert result.node_id=="node-3"
    else:
        result=HydraLiveNodeClient("node1",p["url"],timeout_seconds=p.get("timeout",2)).vote("a"*64,"policy-v1",context=p["context"])
        assert result["valid"] and result["decision"]=="ALLOW"
except Exception as e:
    reason=str(e)
    if not re.fullmatch(r"hydra_remote_transport_authorization_[a-z_]+",reason):
        reason=type(e).__name__
    print(json.dumps({"admitted":False,"reason":reason}))
else:
    print(json.dumps({"admitted":True,"reason":"ALLOW"}))
