'''
Example Hello MISP - test connection to MISP and

David Girard, Trend Micro MISP Internal Workshop. Adapted for Hackfest.ca event Nov 2nd 2018

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

# remove anoying ssl warning messages in console
import urllib3
urllib3.disable_warnings()

api_key = 'D2pQjdpDN7ZEMIcwq1TwhEuL5GlWkKA0g3VlkEPq'  # Publisher role for AWS Central MISP
api_key2 = '' # Admin role for creating users and my password is not Merl0tPl33ze! , not anymore
misp_url = 'https://ec2-54-157-205-95.compute-1.amazonaws.com/'

api_local_key = '' # add your local key if you want to play local
local_misp_url = '' # add your here

def init(url, key, verif):
    ''' Set up pymisp '''
    try:
        return PyMISP(url, key, verif, 'json')
    except Exception as e:
        print("Can't create pyMISP, verify MISP is running or is accessible. Error : " + str(e))



def add_users():
    ''' Add users to a misp, you need an admin account API key for this'''
    try:
        if api_key2 =='':
            return

        misp = init(misp_url, api_key2, False)
        org_id = "2"  # main one used for training
        role_id = "4" # Publisher

        #trainne1 exist so you need to add 2 to 60
        for i in range (2, 61):
            user = "trainee" + str(i) + "@admin.test"
            misp.add_user(user, org_id, role_id)
        # still to set their passwords, no reset and acknowledge
    except Exception as e:
        print(" Error : " + str(e))


def get_users():
    ''' get user list '''
    try:
        misp = init(misp_url, api_key, False)
        users_list = misp.get_users_list()
        print(users_list)
    except Exception as e:
        print(" Error : " + str(e))


def transform_to_strix(event_json):
    ''' Convert Event JSON to STIX 1.2 '''
    try:
        print("Convert Event JSON to STIX 1.2")
        result = make_stix_package(result, to_xml=True)
        x = etree.parse(result)
        print(etree.tostring(x, pretty_print=True))
    except Exception as e:
        print(" Error : " + str(e))


def main():  # parse zip files containing CSV from DDI appliances
    ''' this is The main!  '''
    try:
        # EX01 Initialize misp library
        misp = init(misp_url, api_key, False)
        # Get Statistics on attributes. Nice to see if our connection to MISP really works
        print('Attribute statistics')
        print(misp.get_attributes_statistics(misp, percentage=True))
        print('')

        # Not an exercice, it is use for lab setup
        add_users() # for the trainer only. You need an Admin key for this. Used to create trainee accounts
        # you need to be an admin too. otherwise you get 'You do not have permission to use this functionality'
        print('User list')
        get_users()

        # EX02 Get an event. Make sure Event 1 exist first. It does in AWS but not in your local
        print("Here is how an event JSON look like : ")
        result = misp.get_event(1)  # Event Id 1 exist in DB
        print(json.dumps(result, sort_keys=True, indent=3) + '\n')

        # Ex03 Convert an event JSON to a STIX 1.2
        transform_to_strix(result)

    except Exception as e:
        print(" Error : " + str(e))


if __name__ == '__main__':
    print('*************************')
    print('Welcome to MISP Workshop')
    print('*************************')
    main()