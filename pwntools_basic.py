from pwn import *

# Make TCP connection
r = remote('host1.dreamhack.games', 18836)

# Build payload
payload = b''

# Send payload
r.send(payload)

# Print received data
data = r.recv(1024)
print(f'Received: {data}')

# p = process('./test')

# p.send(b'A')  # ./test에 b'A'를 입력
# p.sendline(b'A') # ./test에 b'A' + b'\n'을 입력
# p.sendafter(b'hello', b'A')  # ./test가 b'hello'를 출력하면, b'A'를 입력
# p.sendlineafter(b'hello', b'A')  # ./test가 b'hello'를 출력하면, b'A' + b'\n'을 입력

# data = p.recv(1024)  # p가 출력하는 데이터를 최대 1024바이트까지 받아서 data에 저장
# data = p.recvline()  # p가 출력하는 데이터를 개행문자를 만날 때까지 받아서 data에 저장
# data = p.recvn(5)  # p가 출력하는 데이터를 5바이트만 받아서 data에 저장
# data = p.recvuntil(b'hello')  # p가 b'hello'를 출력할 때까지 데이터를 수신하여 data에 저장
# data = p.recvall()  # p가 출력하는 데이터를 프로세스가 종료될 때까지 받아서 data에 저장
