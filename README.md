# Agent Harness starter (proposed skeleton, adapt freely)

Terminal 1:  mitmdump -p 8080 -s addon.py        # first run creates ~/.mitmproxy/mitmproxy-ca-cert.pem
Terminal 2:  python dashboard.py                  # http://localhost:5000
Terminal 3:  python run_agent.py -- <your agent command>

Smoke test without any agent:
  python run_agent.py -- bash -c 'curl -s https://example.com | head -c 80; echo; curl -s https://evil.example.org; echo; sleep 60'

Edit policy.json live to change rules. Demo only against a throwaway sandbox dir.
Files: addon.py (policy+logging), run_agent.py (launch+PID), dashboard.py (UI+Stop), policy.json (rules).
