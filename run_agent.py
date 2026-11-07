"""Wrapper: launch any CLI agent through the harness.
Usage:  python run_agent.py -- <agent command ...>
"""
import os, sys, json, subprocess, signal
HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "state")
PROXY = "http://127.0.0.1:8080"
CA = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

cmd = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else sys.argv[1:]
if not cmd:
    sys.exit("usage: python run_agent.py -- <agent command>")

if os.path.exists(os.path.join(STATE, "STOP")):
    os.remove(os.path.join(STATE, "STOP"))       # new session starts clean

env = dict(os.environ,
    HTTP_PROXY=PROXY, HTTPS_PROXY=PROXY, http_proxy=PROXY, https_proxy=PROXY,
    NODE_EXTRA_CA_CERTS=CA, REQUESTS_CA_BUNDLE=CA, SSL_CERT_FILE=CA, CURL_CA_BUNDLE=CA)

p = subprocess.Popen(cmd, env=env, start_new_session=True)   # own process group => killable as a unit
with open(os.path.join(STATE, "session.json"), "w") as f:
    json.dump({"pid": p.pid, "cmd": " ".join(cmd), "status": "running"}, f)
print(f"[harness] session pid={p.pid} cmd={' '.join(cmd)}")
rc = p.wait()
with open(os.path.join(STATE, "session.json"), "w") as f:
    json.dump({"pid": p.pid, "cmd": " ".join(cmd), "status": "stopped" if rc < 0 else "finished"}, f)
print(f"[harness] exited rc={rc}")
