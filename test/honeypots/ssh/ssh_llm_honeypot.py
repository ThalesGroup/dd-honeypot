import os
from ssh_llm_honeypot_core import DataSSHHoneypot  # You will define this core class elsewhere

class SSHLLMHoneypot(DataSSHHoneypot):
    def __init__(self, port: int = 2222):
        folder = os.path.dirname(__file__)
        super().__init__(folder, port)