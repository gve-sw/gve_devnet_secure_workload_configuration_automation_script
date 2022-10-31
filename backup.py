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
import logging
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
    # Argument Parser
    argparser=ArgumentParser()
    argparser.add_argument('-m','--modules',required=False)
    argparser.add_argument('-a','--all',action='store_true',required=False)
    args=argparser.parse_args()

    logger.debug('Starting Backup Workflow')
    tetration=Tetration(os.getenv('TETRATION_URL'),os.getenv('TETRATION_APP_KEY'),os.getenv('TETRATION_APP_SECRET'))
    try:
        if args.modules:
            tetration.backup(modules=args.modules)
        elif args.all:
            tetration.backup(modules=os.getenv('BACKUP_ALL'))
        else:
            tetration.backup(modules=os.getenv('BACKUP_DEFAULT'))
    except Exception as error:
        logger.error(error)
    finally:
        logger.info('Backup Completed')