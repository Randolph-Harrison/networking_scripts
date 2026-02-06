#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PURPOSE: Updates interface descriptions based on LLDP data grabbed with SNMP. To set up running, a .env file
         with SNMP_USER, SNMP_PASS, and SNMP_PRIV defined needs to be created. 

AUTHOR: Randolph Harrison 

DATE: 2026-02-05

USAGE: python3 renaming_ports.py 

DEPENDENCIES: PySNMP, dotenv
"""

import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from dotenv import load_dotenv
import os
import re

load_dotenv()

# using a global snmp engine, not sure if there needs to be one locally for each function, works regardless
snmp_engine = SnmpEngine()

credentials = UsmUserData(
    userName = os.getenv("SNMP_USER"),
    authKey = os.getenv("SNMP_PASS"),
    privKey = os.getenv("SNMP_PRIV"),
    privProtocol = usmAesCfb128Protocol,
    authProtocol = usmHMACMD5AuthProtocol
)

async def renaming_ports():
    switch = input('Enter switch IP: ')

    # list of lists, contains the port oid and the value (host name pulled from LLDP)
    ap_oid_value_list =  await finding_port_oid(switch)
    
    # using snmp set to change port names
    if_name_oid = "1.3.6.1.2.1.31.1.1.1.18."

    transport_target = await UdpTransportTarget.create((switch, 161))

    for port, name in ap_oid_value_list:
        iterator = await set_cmd(
            snmp_engine,
            credentials,
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(if_name_oid + port), OctetString(name))
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
            print(f"Error indication: {errorIndication}")
        elif errorStatus:
            print(f"Error status: {str(errorStatus)} at {errorIndex}")
        else:
            for varBind in varBinds:
                value = varBind[1]
                print(f"Port {await convert_to_port(switch, port)} name changed to: {value}")

# finding_port_oid is used to find lldp neighbors on a switch, filter out any that don't qualify for regex,
# and then send back a list of lists of OID port number and the actual host name eg.
async def finding_port_oid(switch):
    transport_target = await UdpTransportTarget.create((switch, 161))

    lldp_name_oid = "1.0.8802.1.1.2.1.4.1.1.9"

    iterator = walk_cmd(
        snmp_engine,
        credentials,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity(lldp_name_oid)),
        lexicographicMode = False # this stops the WALK command from going to the next OID outside the scope of the LLDP OID.
    )

    ap_oid_port_list = []

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
                # change the regex to which hosts you'd like to target if they follow a specific pattern
                # if you'd like to just change all hosts that are pulled from LLDP, you can just delete this entire conditional
                search = re.search("ADD REGEX HERE", str(value)) 
                if search:
                    ap_oid_port_list.append([str(oid).split('.')[-2], str(value)])
    return ap_oid_port_list

# this function is used only to convert the port oid to a readable port number.
async def convert_to_port(switch, oid):
    transport_target = await UdpTransportTarget.create((switch, 161))

    port_desc_oid = '1.3.6.1.2.1.31.1.1.1.1.' + oid

    iterator = await get_cmd(
        snmp_engine,
        credentials,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity(port_desc_oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator
    if errorIndication:
        print(f"Error indication: {errorIndication}")
    elif errorStatus:
        print(f"Error status: {str(errorStatus)} at {errorIndex}")
    else:
        for varBind in varBinds:
            value = varBind[1]
            return value

snmp_engine.close_dispatcher()

if __name__ == "__main__":
    asyncio.run(renaming_ports())