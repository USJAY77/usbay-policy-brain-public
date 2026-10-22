"""Ephemeral HTTPS node process. No customer or provider operations."""
import socket,sys

def install():
    def audit(event,args):
        if event in ("socket.bind","socket.connect") and args[0].family in (socket.AF_INET,socket.AF_INET6):
            if args[1][0] not in ("127.0.0.1","::1"):raise RuntimeError("NON_LOOPBACK_BLOCKED")
        if event=="subprocess.Popen":raise RuntimeError("SUBPROCESS_BLOCKED")
    sys.addaudithook(audit)
install()

import http.server,json,pathlib,ssl,sys,os,time
from security.hydra_node_service import evaluate_node_vote
p=pathlib.Path(sys.argv[1])
class Node(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert "hydra_remote_transport_authorization" not in body["context"]
        assert "hydra_transport_mandates" not in body["context"]
        if self.path=="/redirect":
            self.send_response(307);self.send_header("Location","/vote");self.end_headers();return
        assert self.path in ("/vote","/evaluate")
        with (p/"entries").open("a") as f:
            f.write("NODE_ENTRY\n");f.flush()
        if (p/"delay").exists():time.sleep(1)
        node_id=os.getenv("SYNTHETIC_NODE_ID","node1")
        result=evaluate_node_vote(body,node_id=node_id)
        if self.path=="/evaluate":
            result=dict(node_id="node-3",node_role="offline_backup",request_hash=body["request_hash"],
                policy_version=body["policy_version"],decision="allow",reason="synthetic",timestamp=1700000010.0)
        raw=json.dumps(result).encode()
        self.send_response(200);self.end_headers()
        try:self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError):pass
s=http.server.HTTPServer(("127.0.0.1",0),Node)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
c.load_cert_chain(p/"tls.pem",p/"tls.key")
s.socket=c.wrap_socket(s.socket,server_side=True)
(p/"port.pending").write_text(str(s.server_port))
(p/"port.pending").replace(p/"port")
s.serve_forever()
