'''
Example retreive.py MISP - retreive events

'''
import os
import json
from pymisp import PyMISP, tools
from pymisp.tools import load_openioc_file
from pymisp.tools.stix import make_stix_package
from misp_stix_converter.converters.buildMISPAttribute import buildEvent
from misp_stix_converter.converters import convert
from misp_stix_converter.converters.convert import MISPtoSTIX
import lxml.etree as etree


api_key = 'D2pQjdpDN7ZEMIcwq1TwhEuL5GlWkKA0g3VlkEPq'  # Publisher role
misp_url = 'https://ec2-54-157-205-95.compute-1.amazonaws.com/'


def init(url, key, verif):
    try:
        return PyMISP(url, key, verif, 'json')
    except Exception as e:
        print("Can't create pyMISP, verify MISP is running or is accessible. Error : " + str(e))


def main():  # parse zip files containing CSV from DDI appliances
    try:
        # Initialize misp library
        misp = init(misp_url, api_key, False)
        # Get Statistics on attributes. Nice to see if our connection to MISP really works
        print(misp.get_attributes_statistics(misp, percentage=True))

        # Get an event
        result = misp.get_event(1)  # Event Id 1 exist in DB
        print(json.dumps(result, sort_keys=True, indent=3) + '\n')

        # Convert Event JSON to STIX 1.2
        result = make_stix_package(result, to_xml=True)
        x = etree.parse(result)
        print(etree.tostring(x, pretty_print=True))

    except Exception as e:
        print(" Error : " + str(e))


if __name__ == '__main__':
    print('Welcome to Retreive MISP')
    main()