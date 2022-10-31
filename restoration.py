""" Copyright (c) 2020 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
           https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import os
import logging.config
import logging.handlers
from argparse import ArgumentParser
from dotenv import load_dotenv

from tetration import Tetration
import urllib3

load_dotenv()
urllib3.disable_warnings()

logging.config.fileConfig(fname=os.path.join(os.getenv('APP_CONFIG'),'logger.conf'), disable_existing_loggers=False)
logger = logging.getLogger(os.path.basename(__file__))

if __name__=='__main__':
    #Argument Parser
    argparser=ArgumentParser()
    argparser.add_argument('-m', '--modules', required=False)
    argparser.add_argument('-vrf', '--vrf',action='store_true', required=False)
    argparser.add_argument('-a', '--all', action='store_true', required=False)

    # Either one of them is required with first preference to Tar file
    group = argparser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--tarfile')
    group.add_argument('-d', '--directory')

    args=argparser.parse_args()

    logger.debug('Starting Restoration Workflow')
    tetration = Tetration(os.getenv('TETRATION_URL'), os.getenv('TETRATION_APP_KEY'), os.getenv('TETRATION_APP_SECRET'))

    extracted_path=''
    if args.tarfile:
        extracted_path = tetration.extract_tarfile(args.tarfile)
    elif args.directory:
        extracted_path=args.directory
    else:
        logger.error('Either Tarfile or directory is required, check more for help --help')
    try:
        vrf_data=None
        new_vrf_data=None
        if args.vrf==True or os.getenv('SELECTIVE_RESTORE').lower()=='true':
            vrf_id=os.getenv("SELECTED_VRF_ID")
            new_vrf_id=os.getenv("TARGET_VRF_ID")

            vrf_data = tetration.get_vrf_from_backup(extracted_path,vrf_id)
            new_vrf_data=tetration.get_or_create_vrf(extracted_path,vrf_id,new_vrf_id)
            if not vrf_data:
                logger.error('Unable to Get VRF Information from the Backup')
                exit(1)
            if not new_vrf_data:
                logger.error('Unable to Get/Create VRF Information from the Instance')
                exit(1)

        # Restoring resources
        if args.modules:
            tetration.restore(extracted_path, modules=args.modules, vrf=vrf_data, new_vrf=new_vrf_data)
        elif args.all:
            tetration.restore(extracted_path, modules=os.getenv('RESTORE_ALL'), vrf=vrf_data, new_vrf=new_vrf_data)
        else:
            tetration.restore(extracted_path, modules=os.getenv('RESTORE_DEFAULT'), vrf=vrf_data, new_vrf=new_vrf_data)
    except Exception as error:
        logger.error(error)
    finally:
        logger.info('Restoration Completed')