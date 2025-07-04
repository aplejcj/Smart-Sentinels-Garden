import socket
import threading
from datetime import datetime

HOST = '127.0.0.1'
PORT = 10000 

def handle_client(conn):
    with conn:
        while True:
            try:
                data = conn.recv(4096)
                if not data: break
                log_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"[{log_time}] {data.decode('utf-8')}")
            except ConnectionResetError:
                break

def main():
    print(f"--- IronForest Observer Node Listening on {HOST}:{PORT} ---")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle_client, args=(conn,)).start()

if __name__ == "__main__":
    main()