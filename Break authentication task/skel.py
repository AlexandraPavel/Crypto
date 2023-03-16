
    
from pwn import *
import base64 as b64
from time import sleep

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

LOCAL = False  # Local means that you run binary directly

if LOCAL:
    # Complete this if you want to test locally
    r = process("<PATH_TO_PYTHON_CHALLENGE>")
else:
    r = remote("141.85.224.117", 1337)  # Complete this if changed

def read_options():
    """Reads server options menu."""
    r.readuntil(b"Input:")

def get_token():
    """Gets anonymous token as bytearray."""
    read_options()
    r.sendline(b"1")
    token = r.readline()[:-1]
    return b64.b64decode(token)

def login(tag):
    """Expects bytearray. Sends base64 tag."""
    r.readline()
    read_options()
    r.sendline(b"2")
    sleep(0.01) # Uncoment this if server rate-limits you too hard
    r.sendline(b64.b64encode(tag))
    r.readuntil(b"Token:")
    response = r.readline().strip()
    return response



# TODO: Solve challenge
# ..


def str_2_hex(data):
    return ''.join(f'{ord(c):02x}' for c in data)

def byte_2_bin(bval):
    """
      Transform a byte (8-bit) value into a bitstring
    """
    return bin(bval)[2:].zfill(8)

def strxor(a, b):  # xor two strings, trims the longer input
    return ''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b))

def bytes_to_string(bytes_data):
    return bytes_data.decode()  # default utf-8
 
def string_to_bytes(string_data):
    return string_data.encode()  # default utf-8

# BASE64 FUNCTIONS
def b64decode(data):
    return bytes_to_string(base64.b64decode(string_to_bytes(data)))
 
def b64encode(data):
    return bytes_to_string(base64.b64encode(string_to_bytes(data)))

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

elph = "Ephvuln"
anonymous = "Anonymous"
pay = strxor(elph, anonymous)
payload = string_to_bytes(pay)

response = login(payload).decode('utf-8')
token = get_token()

GUEST_NAME = string_to_bytes("Anonymous")
K = byte_xor(token, GUEST_NAME)
C = byte_xor(string_to_bytes("Ephvuln"), K)

# Runda 1
i = 1
start = -1
while 1:
    ban = (b'X' * i) + token[i:]
    ban = ban[: 16]
    pay2 = ban
    response = login(pay2).decode('utf-8')
    if response == "Wrong server secret!":
        start = i - 1
        break
    i += 1

# Runda 2
i = 1
end = -1
while 1:
    ban = token[:i] + (b'X' * i)
    ban = ban[: 16]
    pay2 = ban
    response = login(pay2).decode('utf-8')
    if response != "Wrong server secret!":
        end = i
        break
    i += 1


SERVER_PUBLIC_BANNER = token[start:end]

for c in range (256):
    payload = C + SERVER_PUBLIC_BANNER + c.to_bytes(1, 'big')
    response = login(payload).decode('utf-8')
    if response != "Failed integrity check!":
        break


print(response)

if "CTF" in response:
    print("[*] Found flag:",response)


r.close()