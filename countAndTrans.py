
#!/usr/bin/evn python3
# -*- coding: utf-8 -*-
"""
Created on 1/30/25

@author waldo

"""

import socket
import selectors
import types

sel = selectors.DefaultSelector()

HOST = "127.0.0.1"
PORT = 54400


def convert_word(word):
    vowels = "aeiou"
    if word[0].lower() in vowels:
        return word + "yay"
    else:
        for i, letter in enumerate(word):
            if letter.lower() in vowels:
                return word[i:] + word[:i] + "ay"
        return word + "ay"  # In case there are no vowels

def trans_to_pig_latin(words):
    pig_latin_words = [convert_word(word) for word in words]
    return " ".join(pig_latin_words)

def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            data.outb += recv_data
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            words = data.outb.decode("utf-8").split()
            if words[0] == "count":
                return_data = str((len(words)-1)).encode("utf-8")
            elif words[0] == "translate":
                return_data = trans_to_pig_latin(words[1:])
                return_data = return_data.encode("utf-8")
            else:
                print ("No valid command")
                return_data = "Unknown command".encode("utf-8")
            sent = sock.send(return_data)
            data.outb = data.outb[sent:]

if __name__ == "__main__":
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
    lsock.bind((HOST, PORT))
    lsock.listen()
    print("Listening on", (HOST, PORT))
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)
    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()
