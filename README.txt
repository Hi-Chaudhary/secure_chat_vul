GROUP: GROUP 36 (INTENTIONALLY VULNERABLE VERSION)

MEMBERS:

Noor Arora - A1963789

Tanvi Gupta - A1974804

Shubham Chavan - A1963300

Himanshu Chaudhary - A1961006

Amudhan Jayaprakash - A1943725

CONTACT:

Name: Himanshu Chaudhary
Email: a1961006@adelaide.edu.au
Mobile: 0401771310

Name: Noor Arora
Email: a1963789@adelaide.edu.au
Mobile: 0433807863

Name: Shubham Chavan
Email: a1963300@adelaide.edu.au
Mobile: 0452075445


PROJECT:
ChatOverlay — Secure Overlay Chat (Intentionally Vulnerable Build)
This build intentionally contains backdoors/vulnerabilities for the peer review exercise.

================================================================
REQUIREMENTS
================================================================

Python 3.10+ (3.11 recommended)
pip
Python packages (install via requirements.txt):
websockets>=10.4
pycryptodome>=3.18.0

>> pip install -r requirements.txt

================================================================
2) FILE Structure

/examples/
alpha.json, alice.json, ben.json

/src/
init.py
crypto.py
handlers.py
keymgr.py
main.py
peer.py
protocol.py
replay_protector.py
routing.py
storage.py
user_db.py
utils.py

/tools/
gen_keys.py

README.txt

Protocol.md

requirement.txt

================================================================
3) BUILD / RUN

Keys (generate once per peer):
(please replace <name> with your(user) name , <port> with your port number)

>> python tools/gen_keys.py --peer-id <name>
(example command ->> python tools/gen_keys.py --peer-id alice)

Start a node:
>> python -m src.main --name <name> --port <port> --keys keys/<name>
(example command - >> python -m src.main --name alice --port 9001 --keys keys/alice)


CLI commands inside a node:
/list
/tell --to <peer> --text <message>
/all --text <message>
/file --to <peer> --path <file>
/quit

================================================================
4) LOCAL SYSTEM DEMO EXAMPLE (HUB + 3 MEMBERS ON ONE PC)

Generate keys (hub + 3 members)
>> python tools/gen_keys.py --peer-id alpha-hub
>> python tools/gen_keys.py --peer-id alice
>> python tools/gen_keys.py --peer-id ben
>> python tools/gen_keys.py --peer-id cara

Start the alpha hub (listens on port 9001)
>> python -m src.main --name alpha-hub --port 9001 --keys keys/alpha-hub

Start each member and connect to the hub
(Use localhost if everything runs on one machine. If the hub is on another machine, replace localhost with its IP/hostname.)

on Alice terminal-

>> python -m src.main --name alice --port 9101 --keys keys/alice --peers ws://localhost:9001

on Ben terminal-

>> python -m src.main --name ben --port 9102 --keys keys/ben --peers ws://localhost:9001

on Cara terminal-

>> python -m src.main --name cara --port 9103 --keys keys/cara --peers ws://localhost:9001


then test the commands:
/list
/tell --to alice --text hello
/all --text "hi everyone"
/file --to alice --path path\to\file

================================================================
5) MULTI-PC SETUPS Example (INTEROPERABILITY)

********
Option A — Direct peer-to-peer (recommended for 2 people , here we have taken example of 2 users namely- shubham and himanshu)
********

One-time prep on both PCs
(If you previously pinned keys for the same names)
Delete keys\trustmap.json on both PCs.

Generate keys with each person’s own name:
python tools\gen_keys.py --peer-id himanshu (on Himanshu’s PC)
python tools\gen_keys.py --peer-id shubham (on Shubham’s PC)

Choose listener and dialer
Example: Himanshu listens on port 9001; Shubham dials Himanshu.

On Himanshu’s PC (Terminal 1):
(Windows) open firewall port once (admin):
netsh advfirewall firewall add rule name="chat-9001" dir=in action=allow protocol=TCP localport=9001
(mac) 1- Go to System Settings → Network → Firewall → Options…
    2- Click the “+” icon and add your Python binary (usually /usr/bin/python3 or /Library/Frameworks/Python.framework/Versions/3.x/bin/python3).
    3- Set it to “Allow incoming connections.”

Start node:
python -m src.main --name himanshu --port 9001 --keys keys/himanshu
Find IP (Windows):
ipconfig
Note the IPv4 (e.g., 192.168.1.23)

On Shubham’s PC (Terminal 2):
python -m src.main --name shubham --port 9002 --keys keys/shubham --peers ws://<HIMANSHU_IP>:9001

Test
On either console:
/list
/tell --to himanshu --text "hello from shubham"
…and vice versa:
/tell --to shubham --text "hello from himanshu"
Broadcast:
/all --text "hi team!"

If you are on different networks:

Port-forward TCP 9001 on the listener’s router to the PC.


********
Option B — One PC acts as a hub (for 3+ people)
********

One-time prep
Delete keys\trustmap.json if you previously pinned.
Generate keys:
python tools\gen_keys.py --peer-id alpha-hub
python tools\gen_keys.py --peer-id himanshu
python tools\gen_keys.py --peer-id shubham

Start the hub on Himanshu’s PC
(Windows firewall)
netsh advfirewall firewall add rule name="chat-9001" dir=in action=allow protocol=TCP localport=9001
Start hub:
python -m src.main --name alpha-hub --port 9001 --keys keys/alpha-hub
Find Himanshu’s IPv4 via ipconfig.

Start members and connect to the hub
On Himanshu’s PC (optional self member):
python -m src.main --name himanshu --port 9101 --keys keys/himanshu --peers ws://<HIM_IP>:9001
On Shubham’s PC:
python -m src.main --name shubham --port 9102 --keys keys/shubham --peers ws://<HIM_IP>:9001

Nudge sessions, then chat
From the hub console (optional, helps form link sessions fast):
/tell --to himanshu --text "hub->him"
/tell --to shubham --text "hub->shub"

Now DMs via hub:
(on Himanshu) /tell --to shubham --text "hello via hub"
Group fan-out:
/all --text "hello everyone"

================================================================
6) COMMON PITFALLS & QUICK FIXES

Connection refused / timeouts:

Use the listener’s IPv4, not localhost across machines.

Ensure firewall rule exists for the listening port.

For internet paths, confirm router port forwarding or use Tailscale/ZeroTier.

“fingerprint mismatch … refusing session”:

You regenerated keys after pinning. Delete keys\trustmap.json on all involved nodes and reconnect.

“No session for <peer>”:

Send a tiny message both ways to create link-level sessions.

In hub mode, send a short /tell from hub to each member once.

Display shows messages “from hub” instead of real sender:

Ensure patches that preserve original author are present (this build does).

================================================================
7) SAFETY & ETHICAL NOTE

THIS IS THE INTENTIONALLY VULNERABLE BUILD (for Week 9). It includes at least two planted vulnerabilities/backdoors as per assignment rules. Do NOT run on any production or personal machine. Always use a sandboxed VM or container.

We will disclose details and PoC in Week 11 (reflective commentary).

================================================================
8) LICENSE / ATTRIBUTION

Uses websockets, pycryptodome (see their licenses).

Educational use only.

================================================================
9) CREDITS

Group 36 — Advanced Secure Programming — University of Adelaide (2025)