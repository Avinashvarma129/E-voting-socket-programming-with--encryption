import hashlib
import os
import random
import secrets
import socket
import pickle
import struct
import sys
import threading
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Util.number import getPrime, inverse
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import Salsa20
from Crypto.Util.Padding import pad
from phe import paillier
import phe.encoding

HOST = '127.0.0.1'

class Voter():
    election_id = ''
    collector1_pk = ''
    collector1_pk_length = ''
    collector1_key_hash = ''
    collector1_host = HOST
    collector1_host_length = ''
    collector1_port = ''
    collector2_pk = ''
    collector2_pk_length = ''
    collector2_key_hash = ''
    collector2_host = HOST
    collector2_host_length = ''
    collector2_port = ''
    M = 2
    name1_length = ''
    name1 = ''
    name2_length = ''
    name2 = ''

    def __init__(self, voter_id):
        self.voter_id = int(voter_id)
        voter_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open(f"data/voter{voter_id}_private_key.pem", "wb") as f:
            f.write(voter_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        message_type = b'\x03'
        serialized_key = voter_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_hash = hashlib.sha256(serialized_key).digest()
        self.votr_id = self.voter_id.to_bytes(4, byteorder='big')

        payload = message_type + key_hash + self.votr_id

        random_bytes = os.urandom(32)

        # Sign the payload
        signature = voter_private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        payload_length = struct.pack('>I', len(payload))
        signature_length = struct.pack('>I', len(signature))
        message = payload_length + payload + random_bytes + signature_length + signature
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.connect((HOST, 8000))
        except OSError:
            Administrator.admin_port = int(input("ENTER ADMIN PORT FROM ADMIN SERVER"))
            server.connect((HOST, Administrator.admin_port))
        print("Connected to Admin Server")
        print("Registered Succefully")
        server.sendall(message)
        payload_length = None
        payload = None
        random_bits = None
        signature_length = None
        signature = None

        # Receive payload length
        payload_data = server.recv(2000)
        # print(payload_length_data)
        server.close()
        payload_data = pickle.loads(payload_data)
                
        payload_len = payload_data[0]
        message_type = payload_data[1]
        Voter.election_id = payload_data[2]
        print('Election ID_ADMIN: ',int.from_bytes(Voter.election_id, byteorder="big"))
        Voter.collector1_host_length = payload_data[3]
        print('C1_host_length', int.from_bytes(Voter.collector1_host_length, byteorder="big"))
        Voter.collector1_host = payload_data[4]
        print('C1_host', Voter.collector1_host.decode('utf-8'))
        Voter.collector1_port = payload_data[5]
        print('C1_port', int.from_bytes(Voter.collector1_port, byteorder="big"))
        Voter.collector1_pk_length = payload_data[6]
        print('C1_pk_length', int.from_bytes(Voter.collector1_pk_length, byteorder="big"))
        Voter.collector1_pk = payload_data[7]
        print('C1_pk')
        Voter.collector2_host_length = payload_data[8]
        print('C2_host_length', int.from_bytes(Voter.collector2_host_length, byteorder="big"))
        Voter.collector2_host = payload_data[9]
        print('C2_host', Voter.collector2_host.decode('utf-8'))
        Voter.collector2_port = payload_data[10]
        print('C2_port', int.from_bytes(Voter.collector2_port, byteorder="big"))
        Voter.collector2_pk_length = payload_data[11]
        print('C2_pk_length', int.from_bytes(Voter.collector2_pk_length, byteorder="big"))
        Voter.collector1_pk = payload_data[12]
        print('C2_pk')
        Voter.M = payload_data[13]
        print('M: ', int.from_bytes(Voter.M, byteorder="big"))
        Voter.name1_length = payload_data[14]
        print('name1_length: ', int.from_bytes(Voter.name1_length, byteorder="big"))
        Voter.name1 = payload_data[15]
        print('name1: ', Voter.name1.decode('utf-8'))
        Voter.name2_length = payload_data[16]
        print('name2_length: ', int.from_bytes(Voter.name2_length, byteorder="big"))
        Voter.name2 = payload_data[17]
        print('name2: ', Voter.name2.decode('utf-8'))
        print("random 32bytes")
        print("signature length")
        print("signature")

        print("ELECTION DATA RECEIVED")
        print("REQUESTING SHARES...")
        print("Wait until all the voters get election information to cast vote")
        print('COMPETITOR 1: A')
        print('COMPETITOR 2: B')
        my_vote = input("ENTER YOUR VOTE A OR B: ")
        if my_vote == 'A' or my_vote == 'a':
            my_vote = 1
        else:
            my_vote = 2
        message = [b'vo', my_vote]
        

        self.vote_to_collector(1, message)
        time.sleep(1)
        self.vote_to_collector(2, message)
        
        
    def vote_to_collector(self, collector, vote):
        with open('data/paillier_keys.pkl', 'rb') as f:
            public_key, private_key = pickle.load(f)
        vote = public_key.encrypt(vote[1])

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if collector == 1:
            server.connect((HOST, int.from_bytes(Voter.collector1_port, byteorder="big")))
            print("Sending ballot to collector 1")
            server.sendall(pickle.dumps([b'vo', vote]))
        else:
            server.connect((HOST, int.from_bytes(Voter.collector2_port, byteorder="big")))
            print("Sending ballot to collector 2")
            server.sendall(pickle.dumps([b'vo', vote]))
            print("VOTE CAST SUCCESSFULLY")

class Administrator():
    election_id = ''
    collector1_pk = ''
    collector1_pk_length = ''
    collector1_key_hash = ''
    collector1_host = ''
    collector1_host_length = ''
    collector1_port = ''
    collector2_pk = ''
    collector2_pk_length = ''
    collector2_key_hash = ''
    collector2_host = ''
    collector2_host_length = ''
    collector2_port = ''
    admin_port = ''
    admin_pk = ''
    M = 2
    N = 0
    admin_private_key = ''

    def __init__(self):
        # Generate a election
        election_id = os.urandom(16)
        Administrator.election_id = election_id
        print("***INITIALISING***")

        admin_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        Administrator.admin_private_key = admin_private_key
        with open("data/admin_private_key.pem", "wb") as f:
            f.write(admin_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        # Generate public-private key pair for collectors
        collector1_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open("data/collector1_private_key.pem", "wb") as f:
            f.write(collector1_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        collector2_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open("data/collector2_private_key.pem", "wb") as f:
            f.write(collector2_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        collector1_pk = collector1_private_key.public_key()
        collector2_pk = collector2_private_key.public_key()
        admin_pk = admin_private_key.public_key()
        # collector1_pk_length = len(collector1_pk)
        # collector2_pk_length = len(collector2_pk)
        col1_hash = collector1_pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        col2_hash = collector2_pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        collector1_key_hash = hashlib.sha256(col1_hash)
        collector1_key_hash = collector1_key_hash.digest()
        collector2_key_hash = hashlib.sha256(col2_hash)
        collector2_key_hash = collector2_key_hash.digest()

        collector1_pk_bytes = collector1_pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )  
        collector2_pk_bytes = collector2_pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )        

        Administrator.collector1_pk = collector1_pk_bytes
        Administrator.collector2_pk = collector2_pk_bytes
        Administrator.admin_pk = admin_pk
        # Administrator.collector1_pk_length = collector1_pk_length
        # Administrator.collector2_pk_length = collector2_pk_length
        Administrator.collector1_key_hash = collector1_key_hash
        Administrator.collector2_key_hash = collector2_key_hash

        collector_host = HOST
        Administrator.collector1_host_length = len(collector_host)
        Administrator.collector2_host_length = len(collector_host)

        server_thread = threading.Thread(target=self.admin_server)
        server_thread.start()

    def admin_server(self):
        Administrator.admin_port = 8000
        Administrator.collector1_port = 8001
        Administrator.collector2_port = 8002
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((HOST, int(Administrator.admin_port)))
        except OSError:
            Administrator.admin_port = int(input("ENTER ADMIN PORT"))
            Administrator.collector1_port = int(input("ENTER CONTROLLER 1 PORT"))
            Administrator.collector2_port = int(input("ENTER CONTROLLER 2 PORT"))
            server.bind((HOST, int(Administrator.admin_port)))

        print(f"Admin Server running at 127.0.0.1 : {Administrator.admin_port}")
        print(f"Collector1 Server running at 127.0.0.1 : {Administrator.collector1_port}")
        print(f"Collector2 Server running at 127.0.0.1 : {Administrator.collector2_port}")
        server.listen(10)
        voters = []
        votes = []
        while True:    
            client, address = server.accept()
            t = threading.Thread(target=self.print_numbers, args=(client, address, voters, votes))
            t.start()
     
    def admin_client(self, port, message):
        print(type(message))
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((HOST, port))
        print("SENDING VOTER LIST TO COLLECTOR")
        server.send(message)
        # pickle.dumps

    def print_numbers(self, client, x, voters, votes):
        print(f"Connection Established with - PORT : {x[1]}")
        data = client.recv(1024)

        try:
            data = pickle.loads(data)
            if data[0] == b'W':
                comp1_votes = data[1][0]
                comp2_votes = data[1][1]
                print('**RESULTS**')
                print('Competitor 1: ', comp1_votes)
                print('Competitor 2: ', comp2_votes)
                winner = max([comp1_votes, comp2_votes])
                if winner == comp1_votes:
                    print('Winner : Competitor 1')
                else:
                    print('Winner : Competitor 2')

                client.close()
            else:
                client.send(Administrator.election_id)
                client.close()
        except:
            if not isinstance(data, list) and data.find(b'\x03') != -1:
                 # extract the payload length & payload
                 payload_length = int.from_bytes(data[:4], byteorder='big')
                 payload = data[4:4+payload_length]

                 # extract the random bits
                 random_bits = data[4+payload_length:4+payload_length+32]

                 # extract the signature length
                 signature_length_start = 4+payload_length+32
                 signature_length_end = signature_length_start + 4
                 signature_length = int.from_bytes(data[signature_length_start:signature_length_end], byteorder='big')

                 # extract the signature
                 signature_start = signature_length_end
                 signature_end = signature_start + signature_length
                 signature = data[signature_start:signature_end]

                 # extract the payload contents
                 message_type = int.from_bytes(payload[:4], byteorder='big')
                 key_hash = payload[4:68]
                 voter_id = payload[33:38]
                 print(f'Sending Election Data {int.from_bytes(voter_id, byteorder="big")}')

                 #Generate message to send to voter
                 message_type = b'\x04'
                 election_ID = Administrator.election_id
                 C1_host_length = len(HOST.encode('utf-8')).to_bytes(4, byteorder='big')
                 C1_host = HOST.encode('utf-8')
                 C1_port = Administrator.collector1_port.to_bytes(2, byteorder='big')
                 C1_pk_length = len(Administrator.collector1_pk).to_bytes(4, byteorder='big')
                 C1_pk = Administrator.collector1_pk
                 C2_host_length = len(HOST.encode('utf-8')).to_bytes(4, byteorder='big')
                 C2_host = HOST.encode('utf-8')
                 C2_port = Administrator.collector2_port.to_bytes(2, byteorder='big')
                 C2_pk_length = len(Administrator.collector2_pk).to_bytes(4, byteorder='big')
                 C2_pk = Administrator.collector2_pk
                 M = (2).to_bytes(1, byteorder='big')
                 name1 = 'Competitor 1'.encode('utf-8')
                 name1_length = len(name1).to_bytes(4, byteorder='big')
                 name2 = 'Competitor 2'.encode('utf-8')
                 name2_length = len(name2).to_bytes(4, byteorder='big')
                 response = b''
                 random_bits = secrets.token_bytes(32)
                 hash_value = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
                 hash_value.update(response + random_bits)
                 digest = hash_value.finalize()
                 signature = Administrator.admin_private_key.sign(
                     digest,
                     padding.PKCS1v15(),
                     hashes.SHA256()
                 )
                 # send the signed response message
                 response_length = len(response).to_bytes(4, byteorder='big')
                 signature_length = len(signature).to_bytes(4, byteorder='big')
                
                 client.sendall(pickle.dumps([response_length, message_type , election_ID , 
                                                 C1_host_length , C1_host , C1_port , C1_pk_length , C1_pk,
                                                 C2_host_length , C2_host , C2_port , C2_pk_length , C2_pk,
                                                 M , name1_length , name1 , name2_length, name2, random_bits,
                                                 signature_length, signature]))
                 with open(f'data/voter{int.from_bytes(voter_id, byteorder="big")}_private_key.pem', "rb") as f:
                     pem_data = f.read()
                     voter_private_key = serialization.load_pem_private_key(
                     pem_data,
                     password=None
                 )
                 public_key = voter_private_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                 public_key_len = len(voter_private_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)).to_bytes(4, byteorder="big")
                 voters.extend([voter_id, public_key_len, public_key])
                 # voter_pk = voter_private_key.public_key()
                 if len(voters) == 5:
                     print('**REGISTRATION PERIOD ENDED**')
                     print('**GENERATING LIST OF VOTERS FOR COLLECTORS**')
                     #Generate message for collectors
                     message = [b'\x05', Administrator.election_id]
                     for i in range(len(voters)):
                         message.append(voters[i])
                    
                     signature = Administrator.admin_private_key.sign(
                         pickle.dumps(message),
                         padding.PSS(
                             mgf=padding.MGF1(hashes.SHA256()),
                             salt_length=padding.PSS.MAX_LENGTH
                         ),
                         hashes.SHA256()
                     )
                    
                     signature_len = len(bytes.fromhex(signature.hex())).to_bytes(4, byteorder="big")
                     x = [secrets.token_bytes(32), signature_len, bytes.fromhex(signature.hex())]
                     # message = message.extend()
                     print('**SENDING LIST OF VOTERS FOR COLLECTOR1**')
                     for i in x:
                         message.append(i)
                     self.admin_client(Administrator.collector1_port, pickle.dumps(message))
                     time.sleep(1)
                     print('**SENDING LIST OF VOTERS FOR COLLECTOR2**')
                     self.admin_client(Administrator.collector2_port, pickle.dumps(message))
                     time.sleep(1)
                     print('**COLLECTOR 1 TO INITIALISE PAILIER ONCE ALL COLLECTORS RECEIVE DATA**')
                 client.close()


class Collector():
    election_id = ''
    M = 2
    N = 5
    voters_info = []
    
    paillier_public_key = ''

    def __init__(self, collector_index):
        self.collector_index = collector_index
        self.votes = []
       
        with open(f"data/collector1_private_key.pem", "rb") as f:
            pem_data = f.read()
            collector1_private_key = serialization.load_pem_private_key(
            pem_data,
            password=None
        )
        with open("data/collector2_private_key.pem", "rb") as f:
            pem_data = f.read()
            collector2_private_key = serialization.load_pem_private_key(
            pem_data,
            password=None
        )
        if collector_index == 1:
            self.private_key = collector1_private_key
            self.pk = collector1_private_key.public_key()
            # self.pk_length = len(self.pk)
            # key_hash = hashlib.sha256(self.pk)
            # key_hash = key_hash.digest()
            # self.key_hash = key_hash
            self.other_C_host_length = len(HOST)
            self.other_C_host = HOST
            self.other_C_port = Administrator.collector2_port
            self.other_C_pk = collector2_private_key.public_key()
            # self.other_C_pk_length = len(self.other_C_pk)
            client_thread = threading.Thread(target=self.collector_client)
            server_thread = threading.Thread(target=self.collector_server, args=(self.collector_index, ))
            client_thread.start()
            server_thread.start()
        else:
            self.private_key = collector2_private_key
            self.pk = collector2_private_key.public_key()
            # self.pk_length = len(self.pk)
            # key_hash = hashlib.sha256(self.pk)
            # key_hash = key_hash.digest()
            # self.key_hash = key_hash
            self.other_C_host_length = len(HOST)
            self.other_C_host = HOST
            self.other_C_port = Administrator.collector1_port
            self.other_C_pk = collector1_private_key.public_key()
            # self.other_C_pk_length = len(self.other_C_pk)
            client_thread = threading.Thread(target=self.collector_client)
            server_thread = threading.Thread(target=self.collector_server, args=(self.collector_index, ))
            client_thread.start()
            server_thread.start()
        
    def collector_server(self, collector_index):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        collector_port = 0000
        if int(collector_index) == 1:
            collector_port = 8001
        else:
            collector_port = 8002
        try:
            server.bind((HOST, collector_port))
        except OSError:
            if int(collector_index) == 1:
                Administrator.collector1_port = int(input(f"ENTER PORT FOR COLLECTOR{collector_index} SERVER"))
                collector_port = Administrator.collector1_port
            else:
                Administrator.collector2_port = int(input(f"ENTER PORT FOR COLLECTOR{collector_index} SERVER"))
                collector_port = Administrator.collector2_port
            
            server.bind((HOST, collector_port))
        server.listen(5)
        print(f"COLLECTOR{collector_index} SERVER STARTED at PORT: {collector_port}")
        while True:    
            client, address = server.accept()
            t = threading.Thread(target=self.collector_controller, args=(self.collector_index, client, address))
            t.start()

    def collector_controller(self, collector_index, client, address):
        print(f"Connection Established with - PORT : {address[1]}")
        data = client.recv(6024)
        data = pickle.loads(data)
        if data[0] == (b'\x05'):
            print("FROM ADMIN")
            if int(collector_index) == 2:
                print("COLLECTOR 2 RECEIVED VOTER INFO")
                client.close()
            else:
                print("COLLECTOR 1 RECEIVED VOTER INFO, PREPARING TO INITIALIZE PAILLIER CRYPTO")
                pub_key, priv_key = paillier.generate_paillier_keypair()
                print("PAILLIER INITIALIZED KEY GENERATED")
                with open('data/paillier_keys.pkl', 'wb') as f:
                    pickle.dump((pub_key, priv_key), f)
                self.paillier_public_key = pub_key
                print("IMPLIMENTING LAS")
                client.close()
                
        # voter request shares
        elif data[0] == (b'\x08'):
            key_hash = data[1]
            election_ID = data[2]
            voter_ID = data[3]

            # prepare response
            with open(f'data/voter{int.from_bytes(voter_ID, byteorder="big")}_private_key.pem', "rb") as f:
                pem_data = f.read()
                voter_private_key = serialization.load_pem_private_key(
                pem_data,
                password=None
            )
            voter_pk = voter_private_key.public_key()                
            v_hash = voter_pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            key_hash = hashlib.sha256(v_hash).digest()
            message = [b'\x09', key_hash, Collector.election_id, int.from_bytes(Collector.N, byteorder="big")]

            symmetric_key = os.urandom(32)

            # Encrypt the payload using Salsa20
            cipher = Salsa20.new(key=symmetric_key, nonce=b'\x00'*8)
            payload = pickle.dumps(message)
            payload_length = len(payload)
            payload_encrypted = cipher.encrypt(payload)

            # Encrypt the symmetric key using RSA
            recipient_public_key = voter_pk
            key_encrypted = recipient_public_key.encrypt(int.from_bytes(symmetric_key, byteorder='big'))

            # Sign the message using RSA
            sender_private_key = self.private_key
            h = hashlib.blake2b.new(payload_length.to_bytes(4, byteorder='big') + payload_encrypted + key_encrypted)
            signature = sender_private_key.sign(h)

            # Generate the knowledge proof
            knowledge_proof = sender_private_key.encrypt(int.from_bytes(symmetric_key, byteorder='big'))
            knowledge_proof_length = len(knowledge_proof).to_bytes(4, byteorder='big')

            # Construct the message
            payload_length = len(payload_encrypted).to_bytes(4, byteorder='big')
            key_encrypted_length = len(key_encrypted[0]).to_bytes(4, byteorder='big')
            signature_length = len(signature).to_bytes(4, byteorder='big')

            message = [payload_length, payload_encrypted, key_encrypted_length, key_encrypted[0], signature_length, signature, knowledge_proof_length, knowledge_proof]

        elif data[0] == (b'vo'):
            with open('data/paillier_keys.pkl', 'rb') as f:
                public_key, private_key = pickle.load(f)
            vote = private_key.decrypt(data[1])
            self.votes.append(vote)
            print('VOTE RECEIVED')
            print('Sub-Protocal 1')
            if collector_index == 2:
                print('Sub-Protocal 1 Success')
            if len(self.votes) == 5:
                comp1_votes = 0
                comp2_votes = 0
                for i in self.votes:
                    if i == 1:
                        comp1_votes += 1
                    else:
                        comp2_votes += 1
                client.close()
                self.collector_client([comp1_votes, comp2_votes])
            

        # collector 1 initiate LAS
        else: 
            print("FROM COLLECTOR 1")
            for i in range(len(data)):
                print(data[i])


    def collector2_las_server(collector_port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, collector_port))
        server.listen(5)
        while True:
            client, address = server.accept()
            data = client.recv(2024)
            data = pickle.loads(data)

    def collector_client(self, result=0):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((HOST, 8000))
        if result != 0 and int(self.collector_index) != 2:
            server.sendall(pickle.dumps([b'W', result]))
            server.close()
            return
        else:
            server.sendall(pickle.dumps([b'R']))
            election_id = server.recv(1024)
        Collector.election_id = election_id
        print("Connected to Admin")
        print(f'Election ID: {int.from_bytes(election_id, byteorder="big")}')
        server.close()

    def send_shares():
        # send signed to both collectors
        # message_type TYPE_SHARES
        # key hash
        # election ID
        # N
        ...
    

if __name__ == '__main__':
    # get the service name from the command line arguments
    service_name = sys.argv[1]

    # start the service based on the service name
    if service_name == 'admin':
        admin = Administrator()
    elif service_name == 'collector1':
        collector1 = Collector(1)
    elif service_name == 'collector2':
        collector2 = Collector(2)
    elif service_name.startswith('voter'):
        vote = Voter(sys.argv[1][-1])
    else:
        print('Invalid service name')
    