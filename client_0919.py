import socket
import sys
import threading

HOST = "127.0.0.1"
PORT = 50919
MAX_READ = 8192


def frame_message(payload: str) -> bytes:
    data = payload.encode()
    return f"LEN:{len(data)}\n".encode() + data


def recv_framed(sock: socket.socket) -> str:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(MAX_READ)
        if not chunk:
            return ""
        buf += chunk

    header, rest = buf.split(b"\n", 1)
    if not header.startswith(b"LEN:"):
        return rest.decode(errors="ignore")

    length = int(header[4:].decode())
    while len(rest) < length:
        chunk = sock.recv(MAX_READ)
        if not chunk:
            break
        rest += chunk
    return rest[:length].decode(errors="ignore")


def send_command(host: str, port: int, command: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(frame_message(command))
        print(recv_framed(s))


def stress_test(host: str, port: int):
    def worker(i: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                cmd = f"REGISTER user{i} pass{i}"
                s.sendall(frame_message(cmd))
                print(f"Client {i}: {recv_framed(s)}")
        except Exception as e:
            print(f"Client {i} error: {e}")

    threads = []
    for i in range(10):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def interactive(host: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("Connected. Type commands like REGISTER/LOGIN/LOGOUT/WHOAMI <token>/QUIT")
        while True:
            cmd = input("> ").strip()
            if not cmd:
                continue
            s.sendall(frame_message(cmd))
            print(recv_framed(s))
            if cmd.upper() == "QUIT":
                break


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    if len(sys.argv) > 3 and sys.argv[3] == "--stress":
        stress_test(host, port)
    elif len(sys.argv) > 3:
        send_command(host, port, " ".join(sys.argv[3:]))
    else:
        interactive(host, port)
