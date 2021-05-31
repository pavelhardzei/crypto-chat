import socket
import threading
import random


class Server:
    def __init__(self, ip, port):
        self.__ip = ip
        self.__port = port
        self.__all_clients: dict[int, socket.socket] = {}
        self.__current_channels: list[list] = []

        self.__server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server.bind((self.__ip, self.__port))
        self.__server.listen(0)
        threading.Thread(target=self.__connect_handler).start()
        print("Server started!")

    def __connect_handler(self):
        while True:
            client, address = self.__server.accept()
            if client not in self.__all_clients.values():
                while True:
                    client_id = random.randint(2 ** 63, 2 ** 64 - 1)
                    if client_id not in self.__all_clients.keys():
                        self.__all_clients[client_id] = client
                        break
                threading.Thread(target=self.__message_handler, args=(client, client_id)).start()
                client.send(b'Successful chat connecting!')
                client.send(bytes(str(client_id), encoding='utf-8'))

    def __message_handler(self, client_socket, client_id):
        while True:
            message: bytes = client_socket.recv(1024)
            print(message)

            if message == b'__exit_command__':
                self.__all_clients.pop(client_id)
                break
            if message == b'__fetch_connections__':
                self.__fetch_connections(client_socket)
                continue
            if message == b'__build_channel__':
                self.__build_channel(client_socket, client_id)
                continue
            if message == b'__destroy_channel__':
                self.__destroy_channel(client_socket, client_id)
                continue
            if message == b'__authentication__':
                self.__authentication(client_socket)
                continue
            if message == b'__authentication_success__':
                self.__authentication_success(client_socket, client_id)
                continue

            message_arr = message.decode('utf-8').split('\n')
            destination_id = message_arr[0]

            client_socket.send(b'(You) ' + bytes(message_arr[1], 'utf-8'))
            self.__all_clients[int(destination_id)].send(bytes(message_arr[1], 'utf-8'))

    def __fetch_connections(self, client_socket: socket.socket):
        active_connections = b''
        if len(self.__all_clients) == 1:
            client_socket.send(b'__no_active_connections__')
            return
        client_socket.send(b'__all_connections__')
        for client_id in self.__all_clients.keys():
            if self.__all_clients[client_id] != client_socket:
                active_connections += bytes(str(client_id) + ' ', encoding='utf-8')
        client_socket.send(active_connections)

    def __build_channel(self, client_socket, client_id: int):
        connect_to = int(client_socket.recv(1024).decode('utf-8'))
        open_key = [client_socket.recv(1024),
                    client_socket.recv(1024)]
        if connect_to not in self.__all_clients.keys():
            client_socket.send(b'__build_failed__')
            return
        for channel in self.__current_channels:
            if client_id in channel or connect_to in channel:
                client_socket.send(b'__build_failed__')
                return
        self.__all_clients[connect_to].send(b'__authentication__')
        self.__all_clients[connect_to].send(b'0')
        self.__all_clients[connect_to].send(bytes(str(client_id), encoding='utf-8'))
        self.__all_clients[connect_to].send(open_key[0])
        self.__all_clients[connect_to].send(open_key[1])

    def __authentication_success(self, client_socket, client_id):
        connect_to = int(client_socket.recv(1024).decode('utf-8'))
        client_socket.send(b'__channel_established__')
        client_socket.send(bytes(str(connect_to), 'utf-8'))
        self.__all_clients[connect_to].send(b'__channel_established__')
        self.__all_clients[connect_to].send(bytes(str(client_id), 'utf-8'))
        self.__current_channels.append([client_id, connect_to])

    def __authentication(self, client_socket: socket.socket):
        message = client_socket.recv(1024).decode('utf-8').split('\n')
        interlocutor_id = message.pop(0)
        state = message.pop(0)

        self.__all_clients[int(interlocutor_id)].send(b'__authentication__')
        self.__all_clients[int(interlocutor_id)].send(bytes(state, encoding='utf-8'))
        self.__all_clients[int(interlocutor_id)].send(b'\n'.join([bytes(x, encoding='utf-8') for x in message]))

    def __destroy_channel(self, client_socket, client_id):
        for channel in self.__current_channels:
            if client_id in channel:
                interlocutor_id = channel[1 - channel.index(client_id)]
                self.__current_channels.remove(channel)
                client_socket.send(b'__channel_destroyed__')
                self.__all_clients[interlocutor_id].send(b'__channel_destroyed__')
                break


def main():
    Server("", 8080)


if __name__ == "__main__":
    main()