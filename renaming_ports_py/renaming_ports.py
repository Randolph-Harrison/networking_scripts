#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

"""
PURPOSE: Updates interface descriptions based on LLDP data. To set up running, a .env file
     with SNMP_USER, SNMP_PASS, and SNMP_PRIV defined needs to be created.

AUTHOR: Randolph Harrison | Downstate WAN Department

DATE: 2026-02-05

USAGE: Use the .exe in dist, or run the .py file directly using 'uv run renaming_ports.py'

DEPENDENCIES: PySNMP, dotenv, pyinstaller
"""

import asyncio
from pysnmp.hlapi.v3arch.asyncio import ( # type: ignore
  SnmpEngine,
  UsmUserData,
  usmAesCfb128Protocol,
  usmHMACMD5AuthProtocol,
  UdpTransportTarget,
  ContextData,
  ObjectType,
  ObjectIdentity,
  OctetString,
  get_cmd,
  set_cmd,
  walk_cmd
)
from dotenv import load_dotenv # type: ignore
import os
import re
import platform
import subprocess
import getpass
from netmiko import ConnectHandler #type: ignore

load_dotenv()

SNMP_ENGINE = SnmpEngine()
CREDENTIALS = UsmUserData(
  userName = os.getenv("SNMP_USER"),
  authKey = os.getenv("SNMP_PASS"),
  privKey = os.getenv("SNMP_PRIV"),
  privProtocol = usmAesCfb128Protocol,
  authProtocol = usmHMACMD5AuthProtocol
)
SYS_DESCR = '1.3.6.1.2.1.1.1.0'
IF_NAME = '1.3.6.1.2.1.31.1.1.1.1.'
IF_ALIAS = '1.3.6.1.2.1.31.1.1.1.18.'
IF_DESCR = '1.3.6.1.2.1.2.2.1.2'
LLDP_REM_SYS_DESC = '1.0.8802.1.1.2.1.4.1.1.9'
LLDP_LOC_PORT_ID = '1.0.8802.1.1.2.1.3.7.1.4.'
LLDP_LOC_PORT_SUBTYPE = '1.0.8802.1.1.2.1.3.7.1.3.'
VLAN_PORTS = '1.3.6.1.2.1.17.7.1.4.3.1.2.1005'
RED = "\033[31m"
RESET = "\033[0m"

WARNING_MESSAGE = """
This script relies on the switch having the correct settings for:
  * SNMP
  * LLDP
  * RADIUS (for saving configuration, needs to be off steelbelt) 
  * Correctly configured hostname for the AP on XCC

If multiple switches are failing to save, you may have entered your AD creds incorrectly.
  * An occasional failure to save is normal.

When the script finishes running, double check the output, and see if there are any discrepancies.
If the switch has correct settings, report the switch IP to me.
"""

async def main() -> None:
  print(WARNING_MESSAGE)
  username = input("Enter your AD username: ")
  password = getpass.getpass("Enter your AD password: ", echo_char='*') # type: ignore
  while True:
    switch_input = input("Enter switch IPs separated by commas (no spaces) or type 'q' to quit: ")
    if switch_input == 'q':
      break
    if switch_input == "":
      continue

    switch_list = switch_input.split(',')
    pingable_switches = []

    # checking user input to make sure the switches are pingable.
    for switch in switch_list:
      # this script was created in WSL, so it can work on both linux and windows machines.
      if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(1000), switch]
      else:
        command = ["ping", "-c", "1", "-W", str(1), switch]

      try:
        result = subprocess.run(
          command, 
          stdout=subprocess.PIPE, 
          stderr=subprocess.PIPE, 
          text=True
        )
        
        if result.returncode == 0:
          pingable_switches.append(switch)
        else:
          print(f"{switch} not pingable")
      except Exception:
        print(f"Error pinging to {switch}")

    print()
    for switch in pingable_switches:
      print("---------------------------------------------------")
      print(f"Removing AP port names on {switch}...")
      try: 
        await cleaning_ports(switch)
      except:
        print(f"{RED}SNMP settings for WanView and WanXmcUser are either missing or incorrect{RESET}")
      print()
      print(f"Renaming ports on {switch}...")
      try: 
        await renaming_ports(switch, username, password)
      except:
        print(f"{RED}SNMP settings for WanView and WanXmcUser are either missing or incorrect{RESET}")
      print("---------------------------------------------------")


# this function will go through all the ports that have the AP naming convention already configured, and clear the names.
# it's called first so we have a clean slate to go through and rename the ports.
async def cleaning_ports(switch: str) -> None:
  transport_target = await UdpTransportTarget.create((switch, 161))

  port_infdesc = []

  iterator = walk_cmd(
    SNMP_ENGINE,
    CREDENTIALS,
    transport_target,
    ContextData(),
    ObjectType(ObjectIdentity(IF_ALIAS)),
    lexicographicMode = False 
  )

  async for item in iterator:
    errorIndication, errorStatus, errorIndex, varBinds = item
    if errorIndication:
      print(f"Error indication: {errorIndication}")
    elif errorStatus:
      print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
      for varBind in varBinds:
        oid = varBind[0]
        value = varBind[1]
        if re.search(r"305|3912|3915|4000|9144|9112|[aA][pP]", str(value)):
          port_infdesc.append([str(oid).split('.')[-1], str(value)])
  for port, name in port_infdesc:
    iterator = await get_cmd(
      SNMP_ENGINE,
      CREDENTIALS,
      transport_target,
      ContextData(),
      ObjectType(ObjectIdentity(IF_NAME + port))
    )

    port_string = ""
    errorIndication, errorStatus, errorIndex, varBinds = iterator
    if errorIndication:
      print(f"Error indication: {errorIndication}")
    elif errorStatus:
      print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
      for varBind in varBinds:
        port_string = str(varBind[1])

    iterator = await set_cmd(
      SNMP_ENGINE,
      CREDENTIALS,
      transport_target,
      ContextData(),
      ObjectType(ObjectIdentity(IF_ALIAS + port), OctetString(""))
    )
    errorIndication, errorStatus, errorIndex, varBinds = iterator
    if errorIndication:
      print(f"Error indication: {errorIndication}")
    elif errorStatus:
      print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
      print(f"Port {port_string} name removed: {name}")


# this function does the actual renaming.
# for the 5420 switches, it will have to go back and remove the display-string name, since that OID will rename both the display-string and description-string.
# it will then save the configuration using RPC calls for EXOS and netmiko for non-EXOS
async def renaming_ports(switch: str, username: str, password: str) -> None:
  vendor_name, lldp_dict, vlan_ports = await finding_port_oid(switch)
  transport_target = await UdpTransportTarget.create((switch, 161))

  for name, port_info in lldp_dict.items():
    iterator = await set_cmd(
      SNMP_ENGINE,
      CREDENTIALS,
      transport_target,
      ContextData(),
      ObjectType(ObjectIdentity(IF_ALIAS + port_info[0]), OctetString(name)) 
    )

    errorIndication, errorStatus, errorIndex, _ = iterator

    if errorIndication:
      print(f"Error indication: {errorIndication}")
    elif errorStatus:
      print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
      if port_info[1] in vlan_ports or len(vlan_ports) == 0:
        print(f"Port {port_info[1]} name changed to: {name}")
      else:
        print(f"Port {port_info[1]} name changed to: {name} {RED}(NOT IN VLAN 1005){RESET}")

  print()
  device = {
    'host': switch,
    'username': username,
    'password': password,
    'fast_cli': True,
  }

  if vendor_name and "release-manager" in ' '.join(vendor_name):
    print("Removing display-string from EXOS switch and saving configuration...")
    device['device_type'] = 'extreme_exos'

    commands_list = []
    for _, port_info in lldp_dict.items():
      commands_list.append(f"unconfigure ports {port_info[1]} display-string")

    try:     
      with ConnectHandler(**device) as net_connect:
        for command in commands_list:
          net_connect.send_command(command)
          net_connect.save_config()
        print(f"Display-strings removed and saved configuration")
    except Exception:
      print(f"{RED}ERROR: Saving has failed, manual save is needed on {switch}{RESET}")
  else:
    print(f"Saving config on ERS {switch}...")
    device['device_type'] = 'extreme_ers'

    try:
      with ConnectHandler(**device) as net_connect:
        net_connect.find_prompt()
        net_connect.save_config()
        print(f"Configuration saved")
    except Exception:
      print(f"{RED}ERROR: Saving has failed, manual save is needed on {switch}{RESET}")


# this function is for finding the lldp neighbors and which port number it's on
# this function first figures out if the switch is avaya (4850 switch).
# this needs to be done because it will need a different OID for it's string formatted port numbers (placed into port_numbers_string list).
# an lldp lookup is done and the local port index and lldp name is grabbed for lldp neighbors that are APs (filtered with regex).
# a translation from the local port index to the interface number index is done. we also grab the a readable port string from this walk.
# we then compare the all_index (containing the string formatted port number and the port index) with the port_numbers_string list.
# this will give us the port index of the lldp neighbors, which we need in the renaming_port function to actually go and rename the port correctly.
async def finding_port_oid(switch: str) -> tuple[list[str] | None, dict[str, list[str]], list[str]]:
  transport_target = await UdpTransportTarget.create((switch, 161))

  vendor_name = None

  # GETTING VENDOR 
  iterator = await get_cmd(
    SNMP_ENGINE,
    CREDENTIALS,
    transport_target,
    ContextData(),
    ObjectType(ObjectIdentity(SYS_DESCR))
  )

  errorIndication, errorStatus, errorIndex, varBinds = iterator
  if errorIndication:
    print(f"Error indication: {errorIndication}")
  elif errorStatus:
    print(f"Error status: {str(errorStatus)} at {errorIndex}")
  else:
    for varBind in varBinds:
      vendor_name = str(varBind[1]).split(" ")
  
  # GETTING ALL PORTS THAT HAVE AP IN LLDP NEIGHBOR INFO
  iterator = walk_cmd(
    SNMP_ENGINE,
    CREDENTIALS,
    transport_target,
    ContextData(),
    ObjectType(ObjectIdentity(LLDP_REM_SYS_DESC)),
    lexicographicMode = False 
  )

  lldp_name: list[str] = []
  lldp_index: list[str] = []

  async for item in iterator:
    errorIndication, errorStatus, errorIndex, varBinds = item

    if errorIndication:
      print(f"Error indication: {errorIndication}")
    elif errorStatus:
      print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
      for varBind in varBinds:
        oid: str = str(varBind[0])
        value: str = str(varBind[1])
        if re.search(r"^.{3}\..*\..*$", value):
          lldp_name.append(value)
          lldp_index.append(oid.split('.')[-2])

  # GETTING ALL PORTS THAT ARE ON VLAN 1005
  iterator = await get_cmd(
    SNMP_ENGINE,
    CREDENTIALS,
    transport_target,
    ContextData(),
    ObjectType(ObjectIdentity(VLAN_PORTS)),
    lexicographicMode = False 
  )

  errorIndication, errorStatus, errorIndex, varBinds = iterator
  if errorIndication:
    print(f"Error indication: {errorIndication}")
  elif errorStatus:
    print(f"Error status: {str(errorStatus)} at {errorIndex}")
  else:
    for varBind in varBinds:
      hex_string = varBind[1]
  
  # BIT COMPARISONS FOR PORTS ON VLAN 1005
  bytes_data = bytes(hex_string)
  vlan_ports = []
  for byte_index, byte_value in enumerate(bytes_data):
    for bit_index in range(8):
      if byte_value & (128 >> bit_index):
        port_number = (byte_index * 8) + (bit_index + 1)
        vlan_ports.append(str(port_number))

  # CONVERTING INDEXES TO READABLE STRINGS
  port_numbers_string = await port_to_string(switch, vendor_name, lldp_index)
  vlan_ports = await port_to_string(switch, vendor_name, vlan_ports)

  # GETTING ALL PORTS ON SWITCH AND CONVERTING TO READABLE STRING
  iterator = walk_cmd(
    SNMP_ENGINE,
    CREDENTIALS,
    transport_target,
    ContextData(),
    ObjectType(ObjectIdentity(IF_DESCR)),
    lexicographicMode = False
  )

  all_index = {}

  async for item in iterator:
    errorIndication, errorStatus, errorIndex, varBinds = item

    if errorIndication:
      print(f"Error indication: {errorIndication}")
    elif errorStatus:
      print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
      for varBind in varBinds:
        index_oid = str(varBind[0]).split('.')
        port_parts_vendor = [item for item in str(varBind[1]).split(' ') if item != '']

        if "4850GTS-PWR+" in port_parts_vendor or "4950GTS-PWR+" in port_parts_vendor:
          if "Unit" in port_parts_vendor:
            port = port_parts_vendor[-3] + "/" + port_parts_vendor[-1]
            all_index[port] = index_oid[-1]
          elif "VLAN" not in port_parts_vendor and "Trunk" not in port_parts_vendor and "Out-of-band" not in port_parts_vendor:
            port = "1/" + port_parts_vendor[-1]
            all_index[port] = index_oid[-1]
        else:
          if "Stack" in port_parts_vendor:
            port = port_parts_vendor[-1]
            all_index[port] = index_oid[-1]
          else:
            port = port_parts_vendor[-1]
            all_index[port] = index_oid[-1]

  index_port = []
  for port in port_numbers_string:
    if port in all_index:
      index_port.append([all_index[port], port])
  lldp_final = dict(zip(lldp_name, index_port))

  
  return vendor_name, lldp_final, vlan_ports

# this function is used to translate from the LLDP index to a readable port number
async def port_to_string(switch, vendor_name, lldp_index) -> list[str]:
  transport_target = await UdpTransportTarget.create((switch, 161))
  port_numbers_string = []
  if vendor_name and "Avaya" in vendor_name:
    for port_parts_vendor in lldp_index:
      iterator = await get_cmd(
        SNMP_ENGINE,
        CREDENTIALS,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity(LLDP_LOC_PORT_ID + port_parts_vendor)) # lldpLocPortId OID
      )

      errorIndication, errorStatus, errorIndex, varBinds = iterator
      if errorIndication:
        print(f"Error indication: {errorIndication}")
      elif errorStatus:
        print(f"Error status: {str(errorStatus)} at {errorIndex}")
      else:
        for varBind in varBinds:
          vendor_parts = str(varBind[1]).split(" ")
          if "Unit" in vendor_parts:
            port = vendor_parts[1] + "/" + vendor_parts[3]
            port_numbers_string.append(port)
          else:
            port = "1/" + vendor_parts[1]
            port_numbers_string.append(port)
  else:
    for port_parts_vendor in lldp_index:
      iterator = await get_cmd(
        SNMP_ENGINE,
        CREDENTIALS,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity(LLDP_LOC_PORT_SUBTYPE + port_parts_vendor)) # lldpLocPortIdSubtype OID
      )

      errorIndication, errorStatus, errorIndex, varBinds = iterator
      if errorIndication:
        print(f"Error indication: {errorIndication}")
      elif errorStatus:
        print(f"Error status: {str(errorStatus)} at {errorIndex}")
      else:
        for varBind in varBinds:
          vendor_parts = varBind[1]
          port_numbers_string.append(str(vendor_parts))

  return port_numbers_string 


SNMP_ENGINE.close_dispatcher()

if __name__ == "__main__":
  asyncio.run(main())