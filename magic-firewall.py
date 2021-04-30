#!/usr/bin/env python3

import PySimpleGUI as sg
import subprocess
import sys
import re

PROD = True 

sg.theme('LightBlue3')

menu_def = [['File', ['Close']],
            ['About', ['About'],],
            ['Help', ['Help Link'],]
          ]
direction = ('INPUT', 'OUTPUT')
interface = ('', 'loopback', 'eth0', 'eth1')
protocol = ('', 'TCP', 'UDP', 'UDPLITE', 'ICMP', 'ICMPV6', 'ESP', 'AH', 'SCTP', 'MH')
action = ('ACCEPT', 'DROP', 'REJECT')
quick_options = ['',['Allow Internal to External Network Connections','Allow All Incoming SSH', 'Allow All Outgoing SSH', 'Allow Loopback Connections', 'Allow Incoming HTTP and HTTPS', 'Allow Outgoing HTTPS', 'Set the Table']]

menu_layout = [
  [sg.Menu(menu_def, key='-MENU-')]
]

column_header = [
  [sg.Text('Direction', size=(8, 0), justification='Left', auto_size_text=False, font=('Helvetica',10,'bold')),
  sg.Text('Interface', size=(14,0), justification='Left', auto_size_text=False, font=('Helvetica',10,'bold')),
  sg.Text('Protocol', size=(14,0), justification='Left', auto_size_text=False, font=('Helvetica',10,'bold')),
  sg.Text('Source IP', size=(14,0), justification='Left', auto_size_text=False, font=('Helvetica',10,'bold')),
  sg.Text('Port', size=(11,0), justification='Left', auto_size_text=False, font=('Helvetica',10,'bold')),
  sg.Text('Dest IP', size=(9,0), justification='Left', auto_size_text=False, font=('Helvetica',10,'bold')),
  sg.Text('Port', size=(13,1), justification='Left', auto_size_text=False, font=('Helvetica',10,'bold')),
  sg.Text('Action', size=(8, 1), justification='Left', auto_size_text=False, font=('Helvetica',10,'bold'))]
]

connections_layout = [
  [sg.Checkbox('New Connections', key='-NEWCON-'),
   sg.Checkbox('Established Connections', key='-ESTCON-'),
   sg.Checkbox('Related Connections', key='-RELCON-'),
   sg.Text('', size=(7,0)),
   sg.ButtonMenu('QUICK ADD', quick_options, size=(10, 1), key='-QUICKADD-'),
   sg.Button('BLOCK DOMAIN', size=(12, 1), key='-DOMAIN-')]
]

rule_edit_layout = [
  [sg.Combo(direction, size=(12, 5), readonly=True, enable_events=True, key='-DIRECTION-',auto_size_text=False),
  sg.Combo(interface, size=(12, 10), readonly=True, enable_events=True, key='-INTERFACE-'),
  sg.Combo(protocol, size=(12, 10), readonly=True, enable_events=True, key='-PROTOCOL-', auto_size_text=False),
  sg.Input(key='-SRCIP-', size=(16,1)),
  sg.Input(key='-SPORT-', size=(6,1)),
  sg.Input(key='-DSTIP-', size=(16,1)),
  sg.Input(key='-DPORT-', size=(6,1)),
  sg.Combo(action, size=(10, 5), enable_events=True, readonly=True, key='-ACTION-', auto_size_text=False),
  sg.Button('ADD', key='-ADDRULE-')]
]

status_layout = [sg.Listbox([], size=(110,10), auto_size_text=True, key='-STATUS-'), sg.Button('DELETE', key='-DELRULE-')]

default_buttons = [sg.Button('ACCEPT ALL', key='-ACCEPTALL-'), sg.Button('DROP ALL', key='-DROPALL-'), sg.Button('FLUSH', key='-FLUSH-'), sg.Button('REFRESH TABLES', key='-REFRESH-')]

layout = [[menu_layout], [column_header], [rule_edit_layout], [connections_layout], [status_layout], [default_buttons]]

def popupError(message):
  sg.popup_error(message)

def handleErrors(output_text):
  error_message = ''
  for line in output_text:
    error_index = line.find('unknown')
    if error_index != -1:
      error_message += line[error_index:]
  if error_message != '':
    popupError(error_message)
    return False
  else:
    return True


def runRealCommand(cmd, timeout=None, window=None):
  nop = None

  p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  output = []
  for line in p.stdout:
    line = line.decode(errors='replace' if (sys.version_info) < (3, 5) else 'backslashreplace').rstrip()
    output.append(line)
    window.refresh() if window else nop

  handleErrors(output)
  return (output)

def runCommand(commandStr):
  if PROD:
    runRealCommand(commandStr)

def getCurrentStatus(window):
  if PROD:
    command = 'iptables -S'
  else:
    command = 'cat iptables-t.txt'

  current_status = runRealCommand(command)
  window['-STATUS-'].Update(values=current_status)
  return current_status

window = sg.Window("Magic Firewall Manager", layout, finalize=True)
getCurrentStatus(window)

def addRule(values):
  direction = values['-DIRECTION-']
  if direction == '':
    popupError('Direction field is REQUIRED')
    return False
  
  action = values['-ACTION-']
  if action == '':
    popupError('Action field is REQUIRED')
    return False
  else:
    action = " -j " + values['-ACTION-']
    
  source_ip = values['-SRCIP-']
  dest_ip = values['-DSTIP-']

  if source_ip != '' and not re.match(r'[0-9]+(?:\.[0-9]+){3}', source_ip):
    popupError('Invalid Source IP Address')
    return False
  elif source_ip != '':
    source_ip = " -s " + source_ip
  if dest_ip != '' and not re.match(r'[0-9]+(?:\.[0-9]+){3}', dest_ip):
    popupError('Invalid Destination IP Address')
    return False
  elif dest_ip != '':
    dest_ip = " -d " + dest_ip

  addCommand = 'iptables -A '
  interface = values['-INTERFACE-']
  if 'loopback' in interface:
    interface = interface.replace('loopback', 'lo')
  if interface != '' and direction == 'INPUT':
    interface = ' -i ' + interface
  elif interface != '' and direction == 'OUTPUT':
    interface = ' -o ' + interface

  protocol = values['-PROTOCOL-']
  if protocol != '':
    protocol = ' -p ' + protocol + ' '
  source_port = values['-SPORT-']
  if source_port != '' and not re.match(r'^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])$', source_port):
    popupError('Invalid Source Port')
    return False
  elif source_port != '':
    source_port = " --sport " + values['-SPORT-']
  dest_port = values['-DPORT-']

  if dest_port != '' and not re.match(r'^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])$', dest_port):
    popupError('Invalid Destination Port')
    return False
  elif dest_port != '':
    dest_port = " --dport " + values['-DPORT-']

  is_new = values['-NEWCON-']
  is_established = values['-ESTCON-']
  is_related = values['-RELCON-']

  connections = ''
  if is_new or is_established or is_related:
    connections = '-m conntrack --ctstate '
    conn_list = []
    if is_new:
      conn_list.append('NEW')
    if is_established:
      conn_list.append('ESTABLISHED')
    if is_related:
      conn_list.append('RELATED')

    connections = ' -m conntrack --ctstate ' + ','.join(conn_list)


  ipRule = addCommand + direction + interface + protocol + dest_ip + dest_port + source_ip + source_port + connections + action
  output = runCommand(ipRule)

  return True

def quickAdd(values):
  rule = values['-QUICKADD-']
  command = 'iptables -A '

  if rule == 'Allow Internal to External Network Connections':
    command += 'FORWARD -i eth0 -o eth1 -j ACCEPT'
    runCommand(command)
  elif rule == 'Allow All Incoming SSH':
    command1 = command + 'INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT'
    command2 = command + 'OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT'
    runCommand(command1)
    runCommand(command2)
  elif rule == 'Allow All Outgoing SSH':
    command1 = command + 'OUTPUT -o eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT'
    command2 = command + 'INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT'
    runCommand(command1)
    runCommand(command2)
  elif rule == 'Allow Loopback Connections':
    command1 = command + 'INPUT -i lo -j ACCEPT'
    command2 = command + 'OUTPUT -o lo -j ACCEPT'
    runCommand(command1)
    runCommand(command2)
  elif rule == 'Allow Incoming HTTP and HTTPS':
    command1 = command + 'INPUT -p tcp -m multiport --dports 80,443 -m conntrack -ctstate NEW,ESTABLISHED -j ACCEPT'
    command2 = command + 'OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT'
    runCommand(command1)
    runCommand(command2)
  elif rule == 'Allow Outgoing HTTPS':
    command1 = command + 'OUTPUT -o eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT'
    command2 = command + 'INPUT -i eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT'
    runCommand(command1)
    runCommand(command2)
  elif rule == 'Set the Table':
    command1 = command + 'OUTPUT -p icmp -j DROP'
    command2 = command + 'OUTPUT -p tcp --sport 22 -j ACCEPT'
    command3 = command + 'OUTPUT -p tcp --dport 22 -j ACCEPT'
    command4 = command + 'OUTPUT -p tcp -j DROP'
    runCommand(command1)
    runCommand(command2)
    runCommand(command3)
    runCommand(command4)


def delRule(values):
  if len(values['-STATUS-']) > 0:
    command = 'iptables ' + values['-STATUS-'][0].replace('-A', '-D')
    runCommand(command)
    return True
  return False

def acceptAll():
  commands = []
  commands.append('iptables --policy INPUT ACCEPT')
  commands.append('iptables --policy OUTPUT ACCEPT')
  commands.append('iptables --policy FORWARD ACCEPT')
  for command in commands:
    runCommand(command)

def dropAll():
  commands = []
  commands.append('iptables --policy INPUT DROP')
  commands.append('iptables --policy OUTPUT DROP')
  commands.append('iptables --policy FORWARD DROP')
  for command in commands:
    runCommand(command)

def blockDomain(values, window):
  domain = ''
  command = 'iptables -A OUTPUT -p tcp -m string --string "'
  command2 = '" --algo kmp --to 65535 -j REJECT'
  domain = sg.popup_get_text('Enter domain to block: (eg. website.com)')
  if domain is not None and domain != '':
    runCommand(command + domain + command2)
    getCurrentStatus(window)


def flush():
  command = 'iptables -F'
  runCommand(command)

def processMenuItem(values):
  menuItem = values['-MENU-']
  if menuItem == 'About':
    sg.popup('   About Magic Firewall Manager\n\n                   © 2021\n\n        r00tFind3r   &   3jD1v1', custom_text=('Hell Yeah!', '  Cool!  '), grab_anywhere=True, background_color='LightYellow')

  elif menuItem == 'Help Link':
    sg.popup('Help Screen\n\n\nHave you heard of this website called "Google.com"?\n\n', custom_text=("Ok! I'll check that out!"))


while True:

  event, values = window.read()

  if event == sg.WINDOW_CLOSED or event == 'Close':
    break
  elif event == "-ADDRULE-":
    if addRule(values):
      getCurrentStatus(window)
  elif event == '-DELRULE-':
    if delRule(values):
      getCurrentStatus(window)
  elif event == '-QUICKADD-':
    quickAdd(values)
    getCurrentStatus(window)
  elif event == '-ACCEPTALL-':
    acceptAll()
    getCurrentStatus(window)
  elif event == '-DROPALL-':
    dropAll()
    getCurrentStatus(window)
  elif event == '-FLUSH-':
    flush()
    getCurrentStatus(window)
  elif event == '-REFRESH-':
    getCurrentStatus(window)
  elif event == 'About' or event == 'Close' or event == 'Help Link':
    processMenuItem(values)
  elif event == '-DOMAIN-':
    blockDomain(values, window)


window.close()

