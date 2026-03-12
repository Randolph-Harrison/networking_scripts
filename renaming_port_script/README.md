### Setup and Dependencies
Uses uv as a package manager, Python 3.14
* pysnmp
* dotenv

Add the SNMP credentials to the .env.example and then delete the ".example" out of the file name after

SNMP_USER\
SNMP_PASS\
SNMP_PRIV

### Basic SNMP
SNMP is a protocol that interacts with a device's System MIB (Management Information Base). System MIBs are basically tree structures, usually looking like this:

* 1 - highest level
    * 1.0 
        * 1.0.0
            * etc.
        * 1.0.1
            * etc.
        * etc.
    * 1.1
        * 1.1.0
            * etc.
        * etc.
    * etc

The numbers are called OIDs (Object Identifiers) and are used to grab information in that level. OIDs can store other OIDs, and may not necessarily contain direct information

An example of an OID that is used in the script is: 1.0.8802.1.1.2.1.4.1.1.9\
This OID is for finding the system names for the LLDP neighbors

There are several SNMP commands that are used in this script:
* WALK will "walk" down the system MIB to grab all the OIDs in a specific OID
    * For example, in the OID for LLDP neighbors above, we use this command to actually grab all the LLDP neighbors
* GET grabs a specific OID
* SET will change the value of an OID

### Using pysnmp
Read this: <https://docs.lextudio.com/pysnmp/v7.1/>

### Logic for script
1. Takes a user input of switch IPs, separated by a space, which is then converted into a list to iterate through
2. For some error checking, it tests each IP to make sure it's pingable
3. For each switch, it will scan all the LLDP neighbors, and grab the hostname and port numbers (port number is be represented as an integer) that correspond to the regex filter
4. Assigns the LLDP neighbor hostname and assigns it the port number

Eventually, I want the script to take in a site ID or router IP, and it will automatically update all the switches in that site

*Randolph Harrison*
