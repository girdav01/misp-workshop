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
import random
from random import randint
import string
import requests
import zipfile
import time

# remove anoying ssl warning messages in console
import urllib3
urllib3.disable_warnings()

api_key = 'D2pQjdpDN7ZEMIcwq1TwhEuL5GlWkKA0g3VlkEPq'  # Publisher role for AWS Central MISP
api_key2 = '' # Admin role for creating users and my password is not Merl0tPl33ze! , not anymore
misp_url = 'https://ec2-54-157-205-95.compute-1.amazonaws.com/'

api_local_key = '' # add your local key if you want to play local
local_misp_url = '' # add your here


def randomStringGenerator(size, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))



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
        result = make_stix_package(event_json, to_xml=True)
        x = etree.parse(result)
        print(etree.tostring(x, pretty_print=True))
    except Exception as e:
        print(" Error : " + str(e))


def create_event_api(misp):
    '''
    new_event(distribution=None, threat_level_id=None, analysis=None, info=None, date=None, published=
    False, orgc_id=None, org_id=None, sharing_group_id=None)
    :param misp:
    :return: event
    '''
    try:
        ev = misp.new_event(1, 3, 1, 'Just a random test event ' + randomStringGenerator(8))
        ip= str(randint(0, 255)) + '.' + str(randint(0, 255)) + '.' + str(randint(0, 255)) + '.' + str(randint(0, 255))
        misp.add_ipdst(ev['Event']['id'], ip, comment='test ip dest attribute', to_ids=True)
        misp.publish(ev['Event']['id'],False)
        return ev
    except Exception as e:
        print(" Error : " + str(e))


def get_url_from_honeypots(misp):
    ''' Create an event with malicious url's from honeypot
    '''
    try:
        # bad url source : vxVault security blog in this case
        response = requests.get('http://vxvault.net/URL_List.php')

        html = str(response.content)
        html = response.text
        # remove vxvault header that need to see one url per line
        postString = html.split("\n", 4)[4];
        #print(postString)
        ev = misp.new_event(1, 1, 1, "Create an event with malicious url's from honeypot " + randomStringGenerator(8))
        misp.freetext(ev['Event']['id'], postString)
        misp.publish(ev['Event']['id'], False)
        return ev

    except Exception as e:
        print(" Error : " + str(e))


def add_sandbox_package(misp,vazip, sha1):
    ext = ['cap', 'ioc', 'tix', 'xml', 'tml']
    try:

        ev = misp.new_event(1, 1, 1, "Sandbox analysis for sha1: " + sha1)
         # parse zip files
        eid = int(ev['Event']['id'])
        with vazip as z:
            for f in z.namelist():
                f_type = f[-3:]
                with z.open(f,mode='r',pwd=bytes('virus','utf-8')) as extract_file:
                    cache_file = extract_file.read()

                if f_type in ext:
                    if f.endswith('_ioc.stix'):
                        att_name = 'stix_ioc_'+ sha1 + '_ioc.stix'
                    elif f.endswith('_so.stix'):
                        att_name = 'stix_so_' + sha1 + '_so.stix'
                    elif f.endswith('.xml'):
                        att_name = 'raw_report_' + sha1 + '.xml'
                    elif f.endswith('.pcap'):
                        att_name = 'pcap_' + sha1 + '.pcap'
                    elif f.endswith('.html'):
                        att_name = 'report_' + sha1 + '.html'
                    elif f.endswith('.ioc'):
                        att_name = 'ioc_' + sha1 + '.ioc'
                    # check if the file exist
                    if os.path.isfile(att_name):
                        os.remove(att_name)  # if it does then remove it

                    target = open(att_name, 'wb')
                    target.write(cache_file)
                    target.close()
                    time.sleep(1) # wait for disk cache to happen
                    resp = misp.add_attachment(eid, att_name, category='External analysis', to_ids=False,
                                           comment=att_name)
                    time.sleep(1)
                    os.remove(att_name)
                else:
                    att_name = 'sample_' + sha1
                    resp = misp.add_attachment(eid, cache_file, category='Payload delivery', to_ids=False,
                                            comment=att_name)
                time.sleep(1)
                print('add _attatchment ' + str(resp))

        misp.publish(eid, alert=False)

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
        '''
        # EX02 Get an event. Make sure Event 1 exist first. It does in AWS but not in your local
        print("Here is how an event JSON look like : ")
        result = misp.get_event(1)  # Event Id 1 exist in DB
        print(json.dumps(result, sort_keys=True, indent=3) + '\n')

        # Ex03 Convert an event JSON to a STIX 1.2
        transform_to_strix(result)

        #Ex04 CreateEvent with API
        result = create_event_api(misp)
        print(json.dumps(result, sort_keys=True, indent=3) + '\n')

        #Ex05 CreateEvent with Honeypot data
        result = get_url_from_honeypots(misp)
        print(json.dumps(result, sort_keys=True, indent=3) + '\n')

        #ex06 Attatch sandbox investigation package
        goal_dir = str(os.path.dirname(os.path.abspath(__file__))) + '\Data\DC4220A7EC9D2BA7352DEDB11E5672F8D9DC00A9.zip'
        print(goal_dir)
        archive = zipfile.ZipFile(goal_dir, 'r')
        add_sandbox_package(misp, archive, 'DC4220A7EC9D2BA7352DEDB11E5672F8D9DC00A9')
        '''
    except Exception as e:
        print(" Error : " + str(e))


if __name__ == '__main__':
    print('*************************')
    print('Welcome to MISP Workshop')
    print('*************************')
    main()
