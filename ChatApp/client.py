import tkinter as tk
from typing import Dict, Any, Optional
from modules.ChatClientApp import ChatClientApp
from modules.ChatClient import ChatClient
from modules.config import HOST, PORT, CERT_FILE

def main() -> None:
    root: tk.Tk = tk.Tk()
    client: ChatClient = ChatClient(HOST, PORT, CERT_FILE)
    app: ChatClientApp = ChatClientApp(root, client)
    root.mainloop()

if __name__ == "__main__":
    main()