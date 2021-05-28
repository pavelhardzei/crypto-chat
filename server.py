import time
import socket
import threading


class Server:
    def __init__(self, ip, port):
        self.__ip = ip
        self.__port = port
        self.__all_client = []

        self.__server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server.bind((self.__ip, self.__port))
        self.__server.listen(0)
        threading.Thread(target=self.__connect_handler).start()
        print("Server started!")

    def __connect_handler(self):
        while True:
            client, address = self.__server.accept()
            if client not in self.__all_client:
                self.__all_client.append(client)
                threading.Thread(target=self.__message_handler, args=(client,)).start()
                client.send(bytes("Successful chat connecting!", encoding="utf-8"))
            time.sleep(1)

    def __message_handler(self, client_socket):
        while True:
            message: bytes = client_socket.recv(1024)
            print(message)

            if message == b'__apple_is_fucking_shit__':
                self.__all_client.remove(client_socket)
                break

            for client in self.__all_client:
                if client != client_socket:
                    client.send(message)
                else:
                    client.send(b'(You) ' + message)
            time.sleep(1)


def main():
    Server("", 8080)


if __name__ == "__main__":
    main()