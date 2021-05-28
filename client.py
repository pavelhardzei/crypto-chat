import tkinter as tk
from tkinter import ttk
import socket
from tkinter import messagebox
import threading
import logging


class ClientGui(tk.Tk):

    def __init__(self, *args, **kwargs):
        # Root
        tk.Tk.__init__(self, *args, **kwargs)
        self.title("Crypto Chat")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.__close_window)

        # Tabs
        tabControl = ttk.Notebook(master=self, takefocus=False)

        tab1 = ttk.Frame(master=tabControl)
        tab2 = ttk.Frame(master=tabControl)

        tabControl.add(tab1, text='Chat')
        tabControl.add(tab2, text='Settings')
        tabControl.pack(expand=True, fill=tk.BOTH)

        # tab 1
        # text frame
        text_frame = tk.Frame(master=tab1)

        self.__text_box_tab1 = tk.Text(master=text_frame, state=tk.DISABLED, width=70, height=20)
        self.__text_box_tab1.grid(row=0, column=0, sticky="nsew")
        scrollbar = tk.Scrollbar(master=text_frame)
        scrollbar.grid(row=0, column=1, sticky="ns")
        scrollbar.config(command=self.__text_box_tab1.yview)
        self.__text_box_tab1.config(yscrollcommand=scrollbar.set)

        text_frame.grid(row=0, column=0, padx=10, pady=10)

        # buttons frame
        buttons_frame = tk.Frame(master=tab1)

        buttons_frame.columnconfigure(0, weight=1)
        buttons_frame.columnconfigure(1, weight=1)
        self.__message_var = tk.StringVar()
        tk.Entry(master=buttons_frame, textvar=self.__message_var, font="Times 14") \
            .grid(row=0, column=0, columnspan=2, padx=10, ipady=5, sticky="ew")

        self.__send_button = tk.Button(master=buttons_frame, text="Send",
                                       font="Times 14", state=tk.DISABLED, command=self.__send_message)
        self.__send_button.grid(row=1, column=0, pady=10, padx=10, ipady=2, sticky="ew")
        tk.Button(master=buttons_frame, text="Clear", font="Times 14",
                  command=lambda: self.__clear_text_box_tab1()) \
            .grid(row=1, column=1, pady=10, padx=10, ipady=2, sticky="ew")

        self.__disconnect_button = tk.Button(master=buttons_frame, text="Disconnect",
                                             font="Times 14", state=tk.DISABLED, command=self.__disconnect)
        self.__disconnect_button.grid(row=2, column=0, columnspan=2, sticky="we", padx=10, ipady=2, pady=10)

        buttons_frame.grid(row=1, column=0, sticky="nsew")

        # tab 2
        tab2.columnconfigure(0, weight=1)

        self.__ip_entry = tk.Entry(master=tab2, font="Times 14")
        self.__ip_entry.grid(row=0, column=0, pady=5, padx=10, ipady=5, sticky="we")
        self.__port_entry = tk.Entry(master=tab2, font="Times 14")
        self.__port_entry.grid(row=1, column=0, pady=5, padx=10, ipady=5, sticky="we")

        self.__connect_button = tk.Button(master=tab2, text="Connect to the server",
                                          font="Times 14", command=self.__connect_handler)
        self.__connect_button.grid(row=2, column=0, pady=10, padx=10, ipady=2, sticky="ew")

        tab2.rowconfigure(3, weight=1)
        self.__text_box_tab2 = tk.Text(master=tab2, state=tk.DISABLED, width=30, height=10)
        self.__text_box_tab2.grid(row=3, column=0, padx=10, pady=20, sticky="nsew")

        # logging
        logging.basicConfig(filename="std.log", format='%(asctime)s - %(levelname)s - %(message)s',
                            filemode='w')
        self.__logger = logging.getLogger()
        self.__logger.setLevel(logging.DEBUG)

    def __connect_handler(self):
        try:
            if self.__ip_entry.get().strip() == "" or self.__port_entry.get().strip() == "":
                raise Exception("Fill ip and port")

            self.__ip = self.__ip_entry.get().strip()
            self.__port = int(self.__port_entry.get().strip())

            self.__tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__tcp_client.connect((self.__ip, self.__port))
            self.__is_connected = True

            message = self.__tcp_client.recv(1024)
            self.__text_box_tab2.config(state=tk.NORMAL)
            self.__text_box_tab2.delete('1.0', tk.END)
            self.__text_box_tab2.insert(index='end', chars=message.decode('utf-8') + '\n')
            self.__text_box_tab2.config(state=tk.DISABLED)

            self.__ip_entry.delete(0, tk.END)
            self.__ip_entry.config(state=tk.DISABLED)
            self.__port_entry.delete(0, tk.END)
            self.__port_entry.config(state=tk.DISABLED)
            self.__connect_button.config(state=tk.DISABLED)

            self.__send_button.config(state=tk.NORMAL)
            self.__disconnect_button.config(state=tk.NORMAL)
            self.__is_connected = True

            threading.Thread(target=self.__monitor_message).start()
        except Exception as e:
            messagebox.showinfo("Exception", e)
            self.__logger.error(e)

    def __monitor_message(self):
        while self.__is_connected:
            try:
                message = self.__tcp_client.recv(1024)
                self.__text_box_tab1.config(state=tk.NORMAL)
                self.__text_box_tab1.insert(index='end', chars=message.decode('utf-8') + '\n')
                self.__text_box_tab1.config(state=tk.DISABLED)
            except Exception as e:
                self.__logger.error(e)

    def __send_message(self):
        try:
            if self.__message_var.get().strip() == "":
                return
            self.__tcp_client.send(bytes(self.__message_var.get(), encoding="utf-8"))
            self.__message_var.set("")
        except Exception as e:
            messagebox.showinfo("Exception", e)
            self.__logger.error(e)

    def __disconnect(self):
        try:
            self.__tcp_client.send(b'__exit_command__')
            self.__is_connected = False
            self.__tcp_client.close()

            self.__send_button.config(state=tk.DISABLED)
            self.__disconnect_button.config(state=tk.DISABLED)

            self.__ip_entry.config(state=tk.NORMAL)
            self.__port_entry.config(state=tk.NORMAL)
            self.__connect_button.config(state=tk.NORMAL)
        except Exception as e:
            self.__logger.error(e)

    def __clear_text_box_tab1(self):
        self.__text_box_tab1.config(state=tk.NORMAL)
        self.__text_box_tab1.delete('1.0', tk.END)
        self.__text_box_tab1.config(state=tk.DISABLED)

    def __close_window(self):
        self.__disconnect()
        self.destroy()


def main():
    ClientGui().mainloop()


if __name__ == "__main__":
    main()