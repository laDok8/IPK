import argparse
import os
import socket
import re

# main
parser = argparse.ArgumentParser(description='IPK project')
parser.add_argument('-n', help='IP adresa a cislo portu jmenneho serveru', required=True)
parser.add_argument('-f', help='SURL souboru pro stazeni. Protokol v URL je vzdy fsp', required=True)
args = parser.parse_args()
# check arguments
if 'f' not in args or 'n' not in args:
    print('error: arg missing')
    exit(1)
if re.match('^fsp://[\w\-_.]+/.+$', args.f) is None or re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$', args.n) is None:
    print('error: arg value')
    exit(1)
name_servr = args.n.split(':')
fservr = args.f.split('://')[1].split('/')[0]

# UDP NSP message
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = 'WHEREIS ' + fservr
s.settimeout(3)
# wrong IP/port error check
try:
    s.sendto(msg.encode(), (name_servr[0], int(name_servr[1])))
    resp = s.recv(1024)
except:
    print('error: fail NSP')
    exit(1)
s.close()

resp = resp.decode()
if resp.split(' ')[0] != 'OK':
    print('error: NSP recv')
    exit(1)
fservrIP = resp.split(' ')[1]
fservr_tuple = fservrIP.split(':')
file = args.f.split('://')[1].split('/', 1)[1]
# get_all
files_down = ['index'] if (file[0] == '*' and len(file) == 1) or (file.endswith('/*') and len(file) >= 1) else [file]

# TCP - FSP - i append to files_down if needed
getAll = False

for item in files_down:
    if item.strip() == '':
        continue
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((fservr_tuple[0], int(fservr_tuple[1])))
    msg = 'GET ' + item + ' FSP/1.0\r\n' + 'Hostname: ' + fservr + '\r\n' + 'Agent: xdokou14\r\n\r\n'
    s.send(msg.encode())

    # get whole message may recieve it in chunks
    lines = b''
    while True:
        message = s.recv(4096)
        if not message:
            break
        lines += message
    lines = lines.split(b'\r\n', 3)
    s.close()
    if lines[0] != b'FSP/1.0 Success' or len(lines) != 4:
        print('error:' + lines[0].decode())
        exit(1)
    length = int(lines[1].decode().replace("Length:", ""))
    # remove header
    lines = lines[3]
    # check length
    if length != len(lines):
        print('error: length mismatch')
        exit(1)

    # get all - apend files ( only once)
    if item == 'index' and file[-1] == '*' and getAll is False:
        tmp_list = [x for x in (lines.decode().split('\r\n')) if x.startswith(file[:-1])]
        files_down.extend(tmp_list)
        getAll = True
        continue

    # write to file ( with dir structure)
    try:
        path = os.path.dirname(item).replace(os.path.dirname(file), '', 1)
        # in get-all need to create dir to avoid colision
        if len(path) != 0:
            if path.startswith('/'):
                path = path[1:]
            if not os.path.exists(path):
                os.makedirs(path)
            path += '/'
        fp = open(path + os.path.basename(item), 'wb')
        fp.write(lines)
        fp.close()
    except:
        print('error: file write')
        exit(1)
