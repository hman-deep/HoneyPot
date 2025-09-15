# Libraries 
import logging 
from logging.handlers import RotatingFileHandler 
import socket
import paramiko 
import threading

# Constants

logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

host_key = paramiko.RSAKey(filename='server.key')

# Loggers & Logging Files
# We have log the Username, IP, Password into a file 

funnel_logger = logging.getLogger('FunnelLogger') # Thats the file log file where the logs are goin g to save (with getLogger) here we are going to store the Username, Ip Password
funnel_logger.setLevel(logging.INFO) # Set the level of logs which is gone be INFO - It provide the general Information of logs
funnel_handler = RotatingFileHandler('audits.log', maxBytes=1000000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredslLogger') # Thats the file log file where the logs are goin g to save (with getLogger) But, here the commands are going to save
creds_logger.setLevel(logging.INFO) # Set the level of logs which is gone be INFO - It provide the general Information of logs
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=1000000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# Emulateed Shell - Creating a emulated shell as well as that SSH server with paramiko

def emulated_shell(channel, client_ip) : # CHANNEL - way to communicate or sending dialog maaseges and strings
    channel.send(b'corporate.jumpbox2$ ') # this is will pop up when an attacker 
    command = b""
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()
        
        command += char

        if char == b'\r':
            if command.strip() == b'exit':
                response = b'\n' + b'Goodbye!' + b'\r\n'
                channel.close()

            elif command.strip() == b'pwd':
                response = b'\n' + b'\\usr\\locall' + b'\r\n'
                creds_logger.info(f"Command {command.strip()}" + "executed by " + f"{client_ip}")

            elif command.strip() == b'whoami':
                response = b'\n' + b'corpuser1' + b'\r\n'
                creds_logger.info(f"Command {command.strip()}" + "executed by " + f"{client_ip}")
            
            elif command.strip() == b'ls':
                response = b'\n' + b'jumpbox1.conf' + b'\r\n'
                creds_logger.info(f"Command {command.strip()}" + "executed by " + f"{client_ip}")
        
            elif command.strip() == b'cat jumpbox1.conf':
                response = b'\n' + b'Go to deeboodah.com.' + b'\r\n'
                creds_logger.info(f"Command {command.strip()}" + "executed by " + f"{client_ip}")
            
            else:
                response = b'\n' + bytes(command.strip()) + b'\r\n'
                creds_logger.info(f"Command {command.strip()}" + "executed by " + f"{client_ip}")
            
            channel.send(response)
            channel.send(b'corpuser.jumpbox2$ ')
            command = b""

# SSH Server + Socket 

class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username = None, input_password = None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, channel):
        if kind =='session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auth(self):
        return "password"
    
    def check_auth_password(self, username, password):

        funnel_logger.info(f"Client {self.client_ip} attempted connection with " + f"username: {username}, " + f"password : {password}")
        creds_logger.info(f"{self.client_ip}, {username}, {password}")

        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
            
        else:
            return paramiko.AUTH_SUCCESSFUL
            
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True
    
def client_handle(client, addr, username, password):
    
    client_ip = addr[0]
    print(f"{client_ip} hhas connected to the server.")

    try:
        
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)
        channel = transport.accept(100)

        if channel is None:

            print("No channel was opened.")

        standard_banner = b"Welcome to Ubuntu 22.04 LTs (Jammy Jellyfish)!\r\n\r\n"

        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error :

        print(error)
        print("!!! Error !!!")

    finally:
        try:

            transport.close()

        except Exception as error:

            print(error)
            print("!!! Error !!!")
        
        client.close()



# Prevision SSH-based Honeypot 

def honeypot(address, port, username, password):

    socks = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # Here socket.AF_INET - Tells the connection is from IPv4 and socket.SOCK_STREAM means we are listning on TCP port
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()

        except Exception as error:
            print(error)