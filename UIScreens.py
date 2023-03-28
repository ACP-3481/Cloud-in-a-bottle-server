import json
from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDRaisedButton, MDIconButton, MDFlatButton
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.floatlayout import MDFloatLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.filemanager import MDFileManager
from kivymd.uix.textfield import MDTextField
import os
from kivy.properties import StringProperty
from Server import get_internal_ip, check_port
import public_ip as ip
import socket
import threading
from kivy.clock import Clock
import upnpy
from typing import Optional
import configparser
import hashlib
import binascii
import base64
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import sys
import gc

i_ip = get_internal_ip()
e_ip = ip.get()
i_port = None
e_port = None
destination_folder = ""
config = {
}
class SetupScreen(Screen):
    dialog = None
    def on_press_default_button(self):
        if not self.dialog:
            self.dialog = MDDialog(
                text="Default Setup not implemented yet",
                buttons=[
                    MDRaisedButton(
                        text="OK",
                        on_release= lambda _: self.dialog.dismiss()
                    ),
                ],
            )
        self.dialog.open()


class DefaultSetup(Screen):
    pass


class DialogContent(MDBoxLayout):
    pass

class FolderSelectionScreen(Screen):
    dialog=None
    def __init__(self, **kwargs):
        super(FolderSelectionScreen, self).__init__(**kwargs)
        self.layout = MDFloatLayout()

        self.title = MDLabel(text="Choose a Folder to Store Cloud Storage Files", pos_hint={'center_x': 0.5,'center_y': 0.9}, width=self.width, halign='center', font_style='H4')
        self.layout.add_widget(self.title)

        # Create a button to open the file manager
        self.file_manager_button = MDRaisedButton(text="Select Folder", on_release=lambda _: self.show_file_manager(), pos_hint={'center_x': 0.5,'center_y': 0.8})
        self.layout.add_widget(self.file_manager_button)

        # Create a label to display the selected folder path
        self.folder_path_label = MDLabel(text="No folder selected yet", pos_hint={'center_x': 0.5,'center_y': 0.5}, width=self.width, halign='center')
        self.layout.add_widget(self.folder_path_label)

        # Create a button to go to the next screen
        self.next_button = MDRaisedButton(text="Next", on_release=self.go_to_next_screen, disabled=True, pos_hint={'center_x': 0.5,'center_y': 0.2})
        self.layout.add_widget(self.next_button)

        self.add_widget(self.layout)

    def show_file_manager(self, *args):
        # Create a file manager instance
        self.file_manager = MDFileManager(
            exit_manager=self.exit_file_manager,
            select_path=self.select_folder_path,
        )
        self.file_manager.add_widget(
            MDIconButton(
                icon="folder-plus",
                on_press=lambda _: self.show_dialog()
            )
                
        )
        if len(args) == 0:
            self.file_manager.show(os.getcwd().replace('\\', '/')) 
        else:
            self.file_manager.show(args[0])
    

    def dialog_ok(self):
        folder_name = self.dialog.content_cls.ids.folder_name_field.text
        folder_path = self.file_manager.current_path + "/" + folder_name
        os.mkdir(folder_path)
        self.exit_file_manager()
        self.show_file_manager(folder_path)
        self.dialog.dismiss()
        

    def show_dialog(self):
        if not self.dialog:
            self.dialog = MDDialog(
                title="Dialog Title",
                type="custom",
                content_cls=DialogContent(),
                buttons=[
                    MDFlatButton(
                        text="CANCEL", on_release= lambda _: self.dialog.dismiss()
                    ),
                    MDFlatButton(
                        text="OK", on_release= lambda _: self.dialog_ok()
                    ),
                ],
            )
        self.dialog.open()
    

    def select_folder_path(self, path):
        # Update the folder path label with the selected path
        self.folder_path_label.text = f"Selected folder: {path}"

        # Enable the "Next" button
        self.next_button.disabled = False

        self.exit_file_manager()

    def exit_file_manager(self, *args):
        # Close the file manager
        self.file_manager.close()

    def go_to_next_screen(self, *args):
        # Get a reference to the screen manager
        screen_manager = self.parent
        config = configparser.ConfigParser()
        config.read(os.path.dirname(os.path.abspath(__file__)) +'\\config.ini')
        config.set('DEFAULT', 'destination_folder', self.file_manager.current_path)
        with open(os.path.dirname(os.path.abspath(__file__)) +'\\config.ini', 'w') as configfile:
                config.write(configfile)
        # Go to the next screen in the screen manager
        screen_manager.current = 'password_screen'

class PasswordScreen(Screen):
    password_text = StringProperty('')
    confirm_password_text = StringProperty('')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.dialog = None

    def show_error_dialog(self):
        self.dialog = MDDialog(
            title="Error",
            text="Password inputs do not match.",
            buttons=[
                MDFlatButton(
                    text="Close", on_release=self.close_dialog
                )
            ],
        )
        self.dialog.open()

    def show_success_dialog(self):
        self.dialog = MDDialog(
            title="Success",
            text="Password saved.",
            buttons=[
                MDFlatButton(
                    text="Close", on_release=self.close_dialog_success
                )
            ],
        )
        self.dialog.open()

    def close_dialog(self, *args):
        self.dialog.dismiss()

    def close_dialog_success(self, *args):
        self.dialog.dismiss()
        self.manager.current = 'customsetup'
        
    def save_password(self):
        password_text = self.ids.password.text
        confirm_password_text = self.ids.confirm_password.text

        if password_text != confirm_password_text:
            self.show_error_dialog()
        else:
            self.show_success_dialog()
            config = configparser.ConfigParser()
            config.read(os.path.dirname(os.path.abspath(__file__)) +'\\config.ini')
            salt = secrets.token_hex(16)
            hash = hashlib.sha256((self.ids.password.text + salt).encode()).hexdigest()
            config.set('DEFAULT', 'salt', salt)
            config.set('DEFAULT', 'hash', hash)
            with open(os.path.dirname(os.path.abspath(__file__)) +'\\config.ini', 'w') as configfile:
                config.write(configfile)





global upnp_status
upnp_status: str = ''
def add_port_mapping(internal_port: int, external_port: int, internal_ip: str, lease_duration: Optional[int] = 0) -> threading.Thread:
    """
    Add a port mapping using UPnP in a separate thread.

    :param internal_port: Internal port number to map.
    :param external_port: External port number to map.
    :param internal_ip: Internal IP address of the client to map.
    :param lease_duration: Duration of the lease (in seconds), after which the port mapping will expire.
                           If not provided or set to 0, the port mapping will have a permanent lease.
    :return: Returns a Thread object that runs the port mapping function.
    """
    def add_port_mapping_thread():
        global upnp_status
        try:
            # Initialize the UPnP client
            client = upnpy.UPnP()

            # Discover UPnP devices on the network
            devices = client.discover()
            mapping_added = False 
            # Loop through each device and add the port mapping
            for device in devices:
                # Check if the device supports the WANIPConnection service
                if 'WANIPConn1' in device.services:
                    # Get the WANIPConnection service
                    wan_ip_service = device.services['WANIPConn1']

                    # Add the port mapping using the WANIPConnection service
                    result = wan_ip_service.AddPortMapping(
                        NewRemoteHost='', 
                        NewExternalPort=external_port, 
                        NewProtocol='TCP', 
                        NewInternalPort=internal_port, 
                        NewInternalClient=internal_ip, 
                        NewEnabled=1, 
                        NewPortMappingDescription='Cloud In A Bottle', 
                        NewLeaseDuration=lease_duration
                    )

                    # Check if the port mapping was added successfully
                    if result['errorCode'] == '0':
                        print("Port mapping added successfully")
                        mapping_added = True
                        upnp_status = 'Open'

            # If no device supports the WANIPConnection service, raise an error
            if not mapping_added:
                upnp_status = 'Failed'
                raise ValueError("No UPnP device found that supports WANIPConnection service")

        except Exception as e:
            # If there is any other error, raise an error with the details
            upnp_status = 'Failed'
            raise ValueError(f"Error: {e}")

    # Create a new thread and start it
    t = threading.Thread(target=add_port_mapping_thread)
    t.start()

class CustomSetup(Screen):
    internal_ip = StringProperty()
    external_ip = StringProperty()
    internal_ip = f"Internal IP: {i_ip}"
    external_ip = f"External IP: {e_ip}"
    dialog = None

    def on_press_manual_config(self):
        print("hello")
        internal_port = self.ids.i_port_input.text
        external_port = self.ids.e_port_input.text
        if not internal_port.isnumeric() or not external_port.isnumeric():
            self.show_alert_dialog("Port values must be numbers")
            return
        global i_port
        global e_port
        i_port = int(internal_port)
        e_port = int(external_port)

        config = configparser.ConfigParser()
        config.read(os.path.dirname(os.path.abspath(__file__)) +'\\config.ini')
        config.set('DEFAULT', 'external_port', external_port)
        config.set('DEFAULT', 'internal_port', internal_port)
        with open(os.path.dirname(os.path.abspath(__file__)) +'\\config.ini', 'w') as configfile:
                config.write(configfile)
        
        self.manager.current = 'port_forwarding'

    def on_press_upnp_button(self):
        add_port_mapping(i_port, e_port, i_ip)
        Clock.schedule_once(lambda _: self.check_upnp_status(), 5)
        self.show_alert_dialog("Trying UPnP. Please wait a few seconds")

    def check_upnp_status(self):
        global upnp_status
        print("UPNP",upnp_status)
        try:
            self.dialog.dismiss()
        except:
            pass
        if upnp_status == 'Failed':
            self.show_alert_dialog("UPnP failed")
            upnp_status = ''
        if upnp_status == 'Open':
            self.show_alert_dialog("UPnP success")
        

    def show_alert_dialog(self, message):
        self.dialog = MDDialog(
            text=message,
            buttons=[
                MDFlatButton(
                    text="OK",
                    on_release= lambda _: self.dialog.dismiss()
                ),
            ],
        )
        self.dialog.open()

class PortForwardingScreen(Screen):
    pass

class PortForwardingInfoScreen(Screen):
    pass

class PortForwardingStepOneScreen(Screen):
    pass

class PortForwardingStepTwoScreen(Screen):
    pass

class PortForwardingStepThreeScreen(Screen):
    pass

class PortForwardingStepFourScreen(Screen):
    pass

class PortForwardingStepFiveScreen(Screen):
    pass

def handle_client_connection(client_socket):
    # encryption setup
    key = RSA.generate(2048)
    rsa_decryptor = PKCS1_OAEP.new(key)
    public_key = key.public_key()
    export_pub_key = public_key.export_key()
    if sys.getsizeof(export_pub_key) < 1024:
        size_difference = 1024 - sys.getsizeof(export_pub_key)
        export_pub_key = (export_pub_key.decode() + (" " * size_difference)).encode()

    # send the public key to the client
    client_socket.send(export_pub_key)
    # Receive the session_key from the client
    session_key = rsa_decryptor.decrypt(base64.b32decode(client_socket.recv(1024).decode().strip().encode()))
    global nonce_int, nonce, session_cipher
    nonce_int = 0
    nonce = nonce_int.to_bytes(32, 'big')
    session_cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    def increment_nonce():
        global nonce_int, nonce, session_cipher
        nonce_int += 1
        print("nonce: ", nonce_int)
        nonce = nonce_int.to_bytes(32, 'big')
        session_cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    def decrement_nonce():
        global nonce_int, nonce, session_cipher
        nonce_int -= 1
        print("nonce: ", nonce_int)
        nonce = nonce_int.to_bytes(32, 'big')
        session_cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    def encrypt_with_padding(data: bytes, session_cipher):
        #if the bytesize of data is 615 or less it will fit within 1024 bytes

        cipher_text = session_cipher.encrypt(data)
        cipher_text_b32 = base64.b32encode(cipher_text)
        size_difference = 1024 - (sys.getsizeof(cipher_text_b32) % 1024)
        cipher_padded = (cipher_text_b32.decode() + " "*size_difference).encode()
        return cipher_padded
    
    def decrypt_with_padding(data: bytes, session_cipher):
        return session_cipher.decrypt(base64.b32decode(data.decode().strip().encode()))
    
    password = decrypt_with_padding(client_socket.recv(1024), session_cipher).decode()
    increment_nonce()
    # check if the password is correct
    config = configparser.ConfigParser()
    config.read(os.path.dirname(os.path.abspath(__file__)) +'\\config.ini')
    salt = config['DEFAULT']['salt']
    hash = hashlib.sha256((password + salt).encode()).hexdigest()
    # if password is not correct, close the connection
    if hash != config['DEFAULT']['hash']:
        client_socket.close()
        raise(ValueError("Incorrect Password"))
    destination_folder = config['DEFAULT']['destination_folder']
    while True:
        # recieve event
        print("helloooooo", nonce_int)
        event = decrypt_with_padding(client_socket.recv(1024), session_cipher).decode()
        increment_nonce()
        match(event):
            case "Upload":
                info = decrypt_with_padding(client_socket.recv(1024),session_cipher).decode()
                increment_nonce()
                filename, name_nonce, data_nonce, size = info.split("|")
                size = int(size)
                size_i = size // 1024
                size_r = size % 1024
                
                with open(f'{destination_folder}/{filename}', 'wb') as f:
                    for i in range(size_i):
                        bytes_read = client_socket.recv(1024) 
                        f.write(bytes_read)
                    bytes_read = client_socket.recv(size_r)
                    f.write(bytes_read)
                with open(f'{destination_folder}/{filename}', 'r+b') as f:
                    session_decrypt_data = session_cipher.decrypt(f.read())
                    increment_nonce()
                    f.seek(0)
                    f.write(session_decrypt_data)
                with open(f'{destination_folder}/{filename}.nonce', 'a') as f:
                    f.write(name_nonce + "\n" + data_nonce)
                print("upload end", nonce_int)

            case "Download":
                file_to_download = decrypt_with_padding(client_socket.recv(1024), session_cipher).decode()
                increment_nonce()
                print('im here', nonce_int)
                file_path = f'{destination_folder}/{file_to_download}'
                with open(file_path, 'rb') as f:
                    data = f.read()
                increment_nonce()
                data_ciphered = session_cipher.encrypt(data)
                decrement_nonce()
                with open(f'{file_path}.nonce', 'r') as f:
                    data = f.read()
                    data_nonce_b32 = data[data.index("\n")+1:].strip().encode()
                data_size = str(sys.getsizeof(data_ciphered)).encode()
                leading_message = data_size + b'|' + data_nonce_b32
                client_socket.send(encrypt_with_padding(leading_message, session_cipher))
                increment_nonce()
                increment_nonce()
                client_socket.send(data_ciphered)


            case "Update":
                file_list = os.listdir(destination_folder)
                not_nonce_list = []
                nonce_list = []
                for item in file_list:
                    if '.nonce' in item:
                        nonce_list.append(item)
                    else:
                        not_nonce_list.append(item)
                name_nonce_pairs = {}
                for i in range(len(not_nonce_list)):
                    filename_b32 = not_nonce_list[i]
                    name_nonce_b32 = ""
                    with open(f"{destination_folder}/{nonce_list[i]}",'r') as f:
                        name_nonce_b32 = f.readline().strip()
                    name_nonce_pairs[filename_b32] = name_nonce_b32
                increment_nonce()
                update = encrypt_with_padding(json.dumps(name_nonce_pairs).encode(), session_cipher)
                decrement_nonce()
                update_size = str(sys.getsizeof(update)).encode()
                client_socket.send(encrypt_with_padding(update_size, session_cipher))
                client_socket.send(update)
                increment_nonce()
                increment_nonce()

            case "End":
                client_socket.close()
        
        
    # close the connection
    client_socket.close()

thread_open = False
def accept_connections():
    global thread_open
    thread_open = True
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((i_ip, i_port))

    # Set a timeout on the socket object before calling accept()
    server_socket.settimeout(10.0)  # Timeout of 5 seconds

    # Listen for incoming connections
    server_socket.listen()
    while True:
        if not thread_open:
            break
        try:
            # Wait for a client connection with timeout
            client_socket, client_address = server_socket.accept()
            print('Accepted connection from {}:{}'.format(client_address[0], client_address[1]))
            # Start a new thread to handle the connection
            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket,))
            client_thread.start()
        except socket.timeout:
            print('Socket timed out waiting for client connections.')
            # Continue waiting for new connections
            continue

accept_thread = threading.Thread(target=accept_connections)
class PortForwardingCheckScreen(Screen):
    port_status = StringProperty()
    def on_enter(self, *args):
        global thread_open
        global port_status
        accept_thread.start()
        #port_open = check_port(e_ip, e_port)
        port_open = True
        if not port_open:
            thread_open = False
        else:
            self.manager.current = 'connection_open'
        port_status = f"{i_ip} {e_ip}"
        return super().on_pre_enter(*args)

class ConnectionOpen(Screen):
    pass

class MenuScreen(Screen):
    pass
