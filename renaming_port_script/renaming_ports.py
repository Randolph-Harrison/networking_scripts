#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PURPOSE: Updates interface descriptions based on LLDP data. To set up running, a .env file
         with SNMP_USER, SNMP_PASS, and SNMP_PRIV defined needs to be created.

AUTHOR: Randolph Harrison | Downstate WAN Department

DATE: 2026-02-05

USAGE: uv run renaming_ports.py (can compile into executable with pyinstaller)

DEPENDENCIES: PySNMP, dotenv, pyinstaller
"""

import asyncio
from pysnmp.hlapi.v3arch.asyncio import ( # type: ignore
    SnmpEngine,
    UsmUserData,
    usmAesCfb128Protocol,
    usmHMACMD5AuthProtocol,
    UdpTransportTarget,
    walk_cmd,
    ContextData,
    ObjectType,
    ObjectIdentity,
    set_cmd,
    OctetString,
    get_cmd
)
from dotenv import load_dotenv
import os
import re
import platform
import subprocess
import httpx

load_dotenv()

SNMP_ENGINE = SnmpEngine()
CREDENTIALS = UsmUserData(
    userName = os.getenv("SNMP_USER"),
    authKey = os.getenv("SNMP_PASS"),
    privKey = os.getenv("SNMP_PRIV"),
    privProtocol = usmAesCfb128Protocol,
    authProtocol = usmHMACMD5AuthProtocol
)


async def main() -> None:
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
                print(f"Issue with {switch}")

        print('\n')
        for switch in pingable_switches:
            print("---------------------------------------------------")
            print(f"Removing AP port names on {switch}...")
            await port_cleaning(switch)
            print("---------------------------------------------------")
            print(f"Renaming ports on {switch}...")
            await renaming_ports(switch)
            print("---------------------------------------------------")
            print('\n')


# this function will go through all the ports that have the AP naming convention already configured, and clear the names.
# it's called first so we have a clean slate to go through and rename the ports.
async def port_cleaning(switch: str) -> None:
    transport_target = await UdpTransportTarget.create((switch, 161))

    port_infdesc = []
    if_name_oid = "1.3.6.1.2.1.31.1.1.1.18." # ifAlias OID

    iterator = walk_cmd(
        SNMP_ENGINE,
        CREDENTIALS,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity(if_name_oid)),
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
        iterator = await set_cmd(
            SNMP_ENGINE,
            CREDENTIALS,
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(if_name_oid + port), OctetString(" "))
        )
        errorIndication, errorStatus, errorIndex, varBinds = iterator
        if errorIndication:
            print(f"Error indication: {errorIndication}")
        elif errorStatus:
            print(f"Error status: {str(errorStatus)} at {errorIndex}")
        else:
            print(f"Removed name \"{name}\" on port {await convert_to_port(switch, port)}")


# this function does the actual renaming.
# for the 5420 switches, it will have to go back and remove the display-string name, since that OID will rename both the display-string and description-string.
async def renaming_ports(switch: str) -> None:
    vendor_name, lldp_dict = await finding_port_oid(switch)

    transport_target = await UdpTransportTarget.create((switch, 161))

    for name, port_info in lldp_dict.items():
        iterator = await set_cmd(
            SNMP_ENGINE,
            CREDENTIALS,
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.31.1.1.1.18." + port_info[0]), OctetString(name)) # ifAlias OID
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
            print(f"Error indication: {errorIndication}")
        elif errorStatus:
            print(f"Error status: {str(errorStatus)} at {errorIndex}")
        else:
            for varBind in varBinds:
                value = str(varBind[1])
                print(f"Port {port_info[1]} name changed to: {value}")
    
    commands_list = [""]
    if vendor_name and "Engine" in ' '.join(vendor_name):
        for name, port_info in lldp_dict.items():
            commands_list.append(f"unconfigure ports {port_info[1]} display-string")
        command_cmd = ';'.join(commands_list).strip(';')
        commands = [command_cmd]


        url = f"http://{switch}/jsonrpc/"
        switch_user = os.getenv("SWITCH_USER")
        switch_pass = os.getenv("SWITCH_PASS")
        
        if not switch_user or not switch_pass:
            print("Error: SWITCH_USER and SWITCH_PASS environment variables must be set")
            return
        
        auth = (switch_user, switch_pass)

        payload = {
            "jsonrpc": "2.0",
            "method": "cli",
            "params": commands,
            "id": 1
        }
        
        async with httpx.AsyncClient(auth=auth) as client:
            try:
                response = await client.post(url, json=payload, timeout=30.0)
                response.raise_for_status()

                result = response.json()
                if "error" in result:
                    print(f"Switch error: {result['error']}")
                else:
                    print(f"Success on removing display-strings")
            except httpx.RequestError as exc:
                print(f"An error occured while requesting {exc.request.url!r}: {exc}")
        


# this function is for finding the lldp neighbors and which port number it's on
# this function first figures out if the switch is avaya (4850 switch).
# this needs to be done because it will need a different OID for it's string formatted port numbers (placed into port_numbers_string list).
# an lldp lookup is done and the local port index and lldp name is grabbed for lldp neighbors that are APs (filtered with regex).
# a translation from the local port index to the interface number index is done. we also grab the a readable port string from this walk.
# we then compare the all_index (containing the string formatted port number and the port index) with the port_numbers_string list.
# this will give us the port index of the lldp neighbors, which we need in the renaming_port function to actually go and rename the port correctly.
async def finding_port_oid(switch: str) -> tuple[list[str] | None, dict[str, list[str]]]:
    transport_target = await UdpTransportTarget.create((switch, 161))

    vendor_name = None

    iterator = await get_cmd(
        SNMP_ENGINE,
        CREDENTIALS,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')) # sysDescr OID
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator
    if errorIndication:
        print(f"Error indication: {errorIndication}")
    elif errorStatus:
        print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
        for varBind in varBinds:
            vendor_name = str(varBind[1]).split(" ")
    
    iterator = walk_cmd(
        SNMP_ENGINE,
        CREDENTIALS,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity("1.0.8802.1.1.2.1.4.1.1.9")), # lldpRemSysDesc OID
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

    port_numbers_string = []
    if vendor_name and "Avaya" in vendor_name:
        for port_parts in lldp_index:
            iterator = await get_cmd(
                SNMP_ENGINE,
                CREDENTIALS,
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity("1.0.8802.1.1.2.1.3.7.1.4." + port_parts)) # lldpLocPortId OID
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
        for port_parts in lldp_index:
            iterator = await get_cmd(
                SNMP_ENGINE,
                CREDENTIALS,
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity("1.0.8802.1.1.2.1.3.7.1.3." + port_parts)) # lldpLocPortIdSubtype OID
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

    iterator = walk_cmd(
        SNMP_ENGINE,
        CREDENTIALS,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.2")), # ifDescr OID
        lexicographicMode = False # this stops the WALK command from going to the next OID outside the scope of the LLDP OID.
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
                port_parts_vendor = str(varBind[0]).split('.')
                index_oid = str(varBind[1]).split(" ")

                if "Avaya" in index_oid:
                    if "Unit" in index_oid:
                        port = index_oid[-4] + "/" + index_oid[-2]
                        all_index[port] = port_parts_vendor[-1]
                    else:
                        port = "1/" + index_oid[-3]
                        all_index[port] = port_parts_vendor[-1]
                elif "Extreme" in index_oid:
                    if "Unit" in index_oid:
                        port = index_oid[-4] + "/" + index_oid[-2]
                        all_index[port] = port_parts_vendor[-1]
                    else:
                        port = "1/" + index_oid[-2]
                        all_index[port] = port_parts_vendor[-1]
                else:
                    if "Stack" in index_oid:
                        port = index_oid[-1]
                        all_index[port] = port_parts_vendor[-1]
                    else:
                        port = index_oid[-1]
                        all_index[port] = port_parts_vendor[-1]
                        
    index_port = []
    for port in port_numbers_string:
        if port in all_index:
            index_port.append([all_index[port], port])
    
    lldp_final = dict(zip(lldp_name, index_port))

    return vendor_name, lldp_final


# this function is used only to convert the port oid to a readable port number.
async def convert_to_port(switch: str, oid: str) -> str:
    transport_target = await UdpTransportTarget.create((switch, 161))

    iterator = await get_cmd(
        SNMP_ENGINE,
        CREDENTIALS,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.31.1.1.1.1." + oid)) # ifName OID
    )

    value = ""
    errorIndication, errorStatus, errorIndex, varBinds = iterator
    if errorIndication:
        print(f"Error indication: {errorIndication}")
    elif errorStatus:
        print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
        for varBind in varBinds:
            value = str(varBind[1])

    return value

SNMP_ENGINE.close_dispatcher()

if __name__ == "__main__":
    asyncio.run(main())