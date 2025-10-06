GROUP: <GROUP NAME>
MEMBERS:
- Noor Arora
- Tanvi Gupta
- Shubham Chanav
- Himanshu Chaudhary
- Amudhan Jayaprakash

PROJECT: Chat App (SECURE Programming)
SUBMISSION: secure baseline (for development). Do NOT include backdoors in this branch.

Requirements:
- Python 3.10+
- pip
- Install: python -m pip install -r requirements.txt

Quick start:
1) Generate demo keys:
   python -m examples/generate_demo_keys

2) Start server:
   python -m src.server --port 9000

3) Start client (in a separate terminal):
   python -m src.client --connect ws://127.0.0.1:9000 --username alice

4) Start another client:
   python -m src.client --connect ws://127.0.0.1:9000 --username bob

Examples:
- To send public message: just type text and press Enter.
- To send private: /pm bob hello, bob
- To quit: /quit

Notes:
- This is the secure baseline. For the Oct 6 submission you will create a *vulnerable* branch and only submit that vulnerable version plus README.txt that clearly marks it as vulnerable.
- Run tests from an isolated VM.
