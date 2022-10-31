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
import json
import tarfile


from datetime import datetime
from tetpyclient import RestClient

logger = logging.getLogger(__name__)

def create_tar(path, name):
    current_dir=os.getcwd()
    os.chdir(os.getenv('APP_BACKUP'))
    with tarfile.open(os.path.join(name+'.tar.gz'), "w:gz") as tar_handle:
        for root, dirs, files in os.walk(name):
            for file in files:
                tar_handle.add(os.path.join(root, file))
    os.chdir(current_dir)


def filterItems(obj, list):
    for ele in list:
        if ele in obj.keys():
            obj.pop(ele)

def updateQuery(query,value,key):
    if query.get('field')==key:
        query["value"]=value
    if query.get('filters',''):
        filter_object=[]
        for i,queryObj in enumerate(query["filters"]):
            filter_object.append(updateQuery(queryObj,value,key))
        query["filters"]=filter_object
    return query

class Tetration():
    def __init__(self,url,api_key,api_secret):
        self.restclient = RestClient(server_endpoint=url,api_key=api_key,api_secret=api_secret,verify=False)
        self.timeout=int(os.getenv('TIMEOUT')) if int(os.getenv('TIMEOUT')) else 30
        logger.debug('Initializing RestClient with TetPyClient')

    def write_to_file(self,directory,name,content):
        with open(os.path.join(directory,name+'.json'),'w') as output_file:
            output_file.write(content)

    def get_applications(self,backup_dir):
        logger.info('Otabining Applications information')
        response = self.restclient.get('/applications',timeout=self.timeout)
        logger.debug(response.text)
        self.write_to_file(backup_dir, os.getenv('BACKUP_APPLICATION_FILE'), response.text)

        application_details = json.loads(response.text)
        application_count = len(application_details)
        logger.info('found {} applications'.format(application_count))

        # application details path
        application_details_path = os.path.join(backup_dir, os.getenv('BACKUP_APPLICATION_FILE') + 's')
        os.makedirs(application_details_path, exist_ok=True)

        # policies details path
        policy_details_path = os.path.join(backup_dir, os.getenv('BACKUP_POLICIES_FILE'))
        os.makedirs(policy_details_path, exist_ok=True)

        for count, application in enumerate(application_details):
            app_response = self.restclient.get('/applications/{}/details'.format(application['id']),timeout=self.timeout)
            if int(app_response.status_code / 100) == 2:
                logger.info('Writing Application {}/{} of {} to {}/{}.json'.format(count + 1, application_count,
                                                                                   application['name'],
                                                                                   application_details_path,
                                                                                   application['id']))
                self.write_to_file(application_details_path, application['id'], app_response.text)

            policy_response = self.restclient.get('/applications/{}/policies'.format(application['id']),timeout=self.timeout)
            if int(policy_response.status_code / 100) == 2:
                logger.info('Writing App Policy {}/{} of {} to {}/{}.json'.format(count + 1, application_count,
                                                                                   application['name'],
                                                                                   policy_details_path,
                                                                                   application['id']))
                self.write_to_file(policy_details_path, application['id'], policy_response.text)

    def get_application_scopes(self,backup_dir,):
        # GET Application Scopes
        logger.info('Otabining Application Scope information')

        response = self.restclient.get('/app_scopes',timeout=self.timeout)
        logger.debug(response.text)
        self.write_to_file(backup_dir, os.getenv('BACKUP_APPLICATION_SCOPE_FILE'), response.text)

        app_scope_details = json.loads(response.text)
        app_scope_count = len(app_scope_details)

        app_scope_path = os.path.join(backup_dir, os.getenv('BACKUP_APPLICATION_SCOPE_FILE') + 's')
        os.makedirs(app_scope_path, exist_ok=True)

        # List out Root Scope Ids
        app_scope_order_path=os.path.join(backup_dir, os.getenv('BACKUP_APPLICATION_SCOPE_ORDER_FILE'))
        os.makedirs(app_scope_order_path, exist_ok=True)
        root_scopes=[]

        # Get Root Scopes from VRF
        response = self.restclient.get('/app_scopes', timeout=self.timeout)
        if response.status_code == 200:
            vrf_data=json.loads(response.text)
            for data in vrf_data:
                if not data["root_app_scope_id"] in root_scopes:
                    root_scopes.append(data["root_app_scope_id"])

        # Get Root Scopes from the App Scope List
        for app_scope in app_scope_details:
            if not app_scope["root_app_scope_id"] in root_scopes:
                root_scopes.append(app_scope["root_app_scope_id"])

        # Get Scope Orders
        root_scopes_count=len(root_scopes)
        logger.info('found {} Root Scopes'.format(root_scopes_count))
        for count, app_scope in enumerate(root_scopes):
            app_response = self.restclient.get('/app_scopes/{}/policy_order'.format(app_scope),timeout=self.timeout)
            if int(app_response.status_code / 100) == 2:
                logger.info(
                    'Writing Root Scope Order {}/{} to {}/{}.json'.format(count + 1, root_scopes_count,
                                                                                  app_scope_order_path,
                                                                                 app_scope))
                self.write_to_file(app_scope_order_path, app_scope, app_response.text)

        logger.info('found {} Application Scopes'.format(app_scope_count))
        for count, app_scope in enumerate(app_scope_details):
            app_response = self.restclient.get('/app_scopes/{}'.format(app_scope['id']),timeout=self.timeout)
            if int(app_response.status_code / 100) == 2:
                logger.info(
                    'Writing Application Scope {}/{} of {} to {}/{}.json'.format(count + 1, app_scope_count,
                                                                                 app_scope['name'], app_scope_path,
                                                                                 app_scope['id']))
                self.write_to_file(app_scope_path, app_scope['id'], app_response.text)
            else:
                logger.error('Error while fetching detailed AppScope {} : {}-{} '.format(app_response.status_code,
                                                                                         app_scope['id'],
                                                                                         app_scope['name']))

    def get_sensors(self,backup_dir):
        # GET Sensors
        logger.info('Otabining Sensor information')
        response = self.restclient.get('/sensors',timeout=self.timeout)
        logger.debug(response.text)
        self.write_to_file(backup_dir, os.getenv('BACKUP_SENSORS_FILE'), response.text)

    def get_inventory_filters(self,backup_dir,vrf=None):
        # GET Inventories
        logger.info('Otabining Inventory Filters information')
        response = self.restclient.get('/filters/inventories',timeout=self.timeout)
        logger.debug(response.text)
        self.write_to_file(backup_dir, os.getenv('BACKUP_INVENTORY_FILTER_FILE'), response.text)

    def get_users(self,backup_dir):
        # GET Users
        logger.info('Otabining Users information')
        response = self.restclient.get('/users',timeout=self.timeout)
        logger.debug(response.text)
        self.write_to_file(backup_dir, os.getenv('BACKUP_USER_FILE'), response.text)

    def get_roles(self,backup_dir):
        # GET Roles
        logger.info('Otabining Roles information')
        response = self.restclient.get('/roles',timeout=self.timeout)
        logger.debug(response.text)
        self.write_to_file(backup_dir, os.getenv('BACKUP_ROLE_FILE'), response.text)

    def get_vrfs_data(self,vrf):
        # GET VRF's
        logger.info('Otabining VRF\'s information')
        response = self.restclient.get('/vrfs', timeout=self.timeout)
        logger.debug(response.text)
        if response.status_code==200:
            vrf_json= json.loads(response.text)
            for vrf_data in vrf_json:
                if int(vrf) == int(vrf_data["id"]):
                    return vrf_data
        return None

    def get_vrfs(self, backup_dir):
        # GET VRF's
        logger.info('Otabining VRF\'s information')
        response = self.restclient.get('/vrfs',timeout=self.timeout)
        logger.debug(response.text)
        self.write_to_file(backup_dir, os.getenv('BACKUP_VRF_FILE'), response.text)

        # GET Collection Rules
        vrf_data=json.loads(response.text)
        collection_path_dir=os.path.join(backup_dir,os.getenv('BACKUP_COLLECTION_FILE'))
        os.makedirs(collection_path_dir,exist_ok=True)
        total_vrfs=len(vrf_data)
        logger.info('Found {} VRF\'s information'.format(total_vrfs))
        for count,vrf in enumerate(vrf_data):
            resp=self.restclient.get('/collection_rules/{}'.format(vrf["name"]),timeout=self.timeout)
            if int(resp.status_code/100) == 2:
                self.write_to_file(collection_path_dir, str(vrf["id"]), resp.text)
                logger.info('Writing Collection Rule {}/{} VRF {} - {}/{}'.format(count+1,total_vrfs,vrf["name"],collection_path_dir,str(vrf["id"])+'.json'))
            else:
                logger.info('Error Getting Collection Rule {}/{} VRF {} - {} '.format(count+1, total_vrfs,vrf["name"],resp.status_code))

    def backup(self,modules):
        # check and create backup folder if not exists
        current_date = datetime.now().strftime('%Y-%m-%d')
        backup_dir=os.path.join(os.getenv('APP_BACKUP'),current_date)
        os.makedirs(backup_dir,exist_ok=True)
        logger.info('Creating backup at location ' + backup_dir)
        resources=modules.split(',')

        for resource in resources:
            # VRF/Tenant Specific
            if 'application' == resource.lower():
                self.get_applications(backup_dir)

            if 'application_scope' == resource.lower():
                self.get_application_scopes(backup_dir)

            if 'inventory_filter' == resource.lower():
                self.get_inventory_filters(backup_dir)

            # Global
            if 'sensor' == resource.lower():
                self.get_sensors(backup_dir)

            if 'user_and_role' == resource.lower():
                self.get_users(backup_dir)
                self.get_roles(backup_dir)

            # VRF + Collection Rules
            if 'vrf' == resource.lower():
                self.get_vrfs(backup_dir)

        logger.info('compressing {} to {} '.format(current_date,backup_dir +'.tar.gz'))
        # Compress the backedup content into tar
        create_tar(backup_dir,current_date)

    def extract_tarfile(self,filepath):
        with tarfile.open(filepath, "r:gz") as tar_handle:
            extract_path=os.path.dirname(tar_handle.getnames()[0])
            tar_handle.extractall(path=os.getenv('APP_RESTORE'))
        return os.path.join(os.getenv('APP_RESTORE'),extract_path)

    # Restoration Part
    def create_application(self, filepath,vrf=None,new_vrf=None):
        app_mapping_path = os.path.join(filepath, os.getenv("APPLICATION_MAPPINGS"))
        os.makedirs(app_mapping_path, exist_ok=True)

        with open(os.path.join(filepath,os.getenv('BACKUP_APPLICATION_FILE') + '.json')) as app:
            data = json.load(app)
            total_apps = len(data)
            for count,app_config in enumerate(data):
                # req_payload = {
                #     "id": app_config["id"],
                #     "app_scope_id": app_config["app_scope_id"],
                #     "name": app_config["name"],
                #     "description": app_config["description"],
                #     "primary": app_config["primary"]
                # }
                with open(os.path.join(filepath,os.getenv('BACKUP_APPLICATION_FILE')+'s',app_config["id"]+'.json')) as json_file:
                    json_data=json_file.read()
                req_payload=json.loads(json_data)

                if vrf:
                    if req_payload["vrf"]["id"]==vrf["id"]:
                        # VRF Details
                        vrf_data={}
                        vrf_data["id"]=new_vrf["id"]
                        vrf_data["name"]=new_vrf["name"]
                        vrf_data["tenant_id"]=new_vrf["tenant_id"]
                        vrf_data["tenant_name"]=new_vrf["tenant_name"]
                        req_payload["vrf"]=vrf_data

                        # Removing
                        elements_to_keep=["app_scope_id","name","description","alternate_query_mode","strict_validation","primary","inventory_filters","absolute_policies","default_policies","catch_all_action"]
                        #elements_to_keep=["app_scope_id","name","description","alternate_query_mode","strict_validation","primary","catch_all_action"]
                        new_req_payload={}
                        for k,v in req_payload.items():
                            if k in elements_to_keep:
                                new_req_payload[k]=v

                        req_payload=new_req_payload
                        # App Scope Details
                        app_scope=self.get_application_scope_leaf(filepath,req_payload["app_scope_id"],vrf,new_vrf)
                        if app_scope:
                            req_payload["app_scope_id"]=app_scope.get("id")
                        # req_payload["app_scope"]=app_scope

                        # Inventory Filters
                        new_ifilters=[]
                        ifilters_elements_to_keep=["id","name","query"]
                        for ifilter in req_payload["inventory_filters"]:
                            filter_dict={}
                            for x,v in ifilter.items():
                                if x in ifilters_elements_to_keep:
                                    if x == "query":
                                        filter_dict[x]=updateQuery(v,new_vrf["id"],"vrf_id")
                                    else:
                                        filter_dict[x]=v
                            new_ifilters.append(filter_dict)
                        req_payload["inventory_filters"]=new_ifilters

                        # Absolute Policies Processing
                        new_policies=[]
                        policy_elements_to_keep=["consumer_filter_id","provider_filter_id","action","l4_params"]
                        l4_params_to_keep=["proto","port","approved"]
                        for policy in req_payload["absolute_policies"]:
                            new_policy={}
                            for k,v in policy.items():
                                if k in policy_elements_to_keep:
                                    if k=="l4_params":
                                        new_l4_params=[]
                                        for l4 in v:
                                            new_l4={}
                                            for x,y in l4.items():
                                                if x in l4_params_to_keep:
                                                    new_l4[k]=v
                                            new_l4_params.append(new_l4)
                                        new_policy[k]= new_l4_params
                                    else:
                                        new_policy[k]=v
                            new_policies.append(new_policy)
                        req_payload["absolute_policies"]=new_policies

                        # Default Processing
                        new_policies = []
                        policy_elements_to_keep = ["consumer_filter_id", "provider_filter_id", "action", "l4_params"]
                        l4_params_to_keep = ["proto", "port", "approved"]
                        for policy in req_payload["default_policies"]:
                            new_policy = {}
                            for k, v in policy.items():
                                if k in policy_elements_to_keep:
                                    if k == "l4_params":
                                        new_l4_params = []
                                        for l4 in v:
                                            new_l4 = {}
                                            for x, y in l4.items():
                                                if x in l4_params_to_keep:
                                                    new_l4[k] = v
                                            new_l4_params.append(new_l4)
                                        new_policy[k] = new_l4_params
                                    else:
                                        new_policy[k] = v
                            new_policies.append(new_policy)
                        req_payload["default_policies"] = new_policies

                    else:
                        continue


                if req_payload:
                    logger.debug('Create Application :' + json.dumps(req_payload))
                    resp = self.restclient.post('/applications', json_body=json.dumps(req_payload),timeout=self.timeout)
                    if resp.status_code==200:
                        logger.info('Restoring Application {}/{} of {}'.format(count + 1, total_apps, app_config['name']))
                        self.write_to_file(app_mapping_path,app_config["id"],resp.text)
                        logger.debug(resp.text)
                    else:
                        logger.error(
                            'Error Restoring Application {}/{} of {} - {},{}'.format(count + 1, total_apps, app_config['name'],resp.status_code,resp.reason))
                else:
                    logger.info('Skip Application {}/{} of {}'.format(count + 1, total_apps, app_config['name']))

    def get_application_scope_leaf(self,filepath,filename,vrf=None,new_vrf=None):
        # If the Mapping Scope is already created
        mapping_path=os.path.join(filepath,os.getenv('APP_SCOPE_MAPPINGS'), filename + ".json")
        if os.path.exists(mapping_path):
            with open(mapping_path) as fp:
                return json.load(fp)
        # return self.create_application_scope_leaf(filepath,filename,vrf,new_vrf)
        return False

    def create_application_scope_leaf(self,filepath,filename,vrf=None,new_vrf=None):

        get_scope_data=self.get_application_scope_leaf(filepath,filename,vrf,new_vrf)
        if get_scope_data:
            logger.info("Application Scope Available {},{}".format(filename, get_scope_data["short_name"]))
            return get_scope_data

        # Load JSON file
        with open(os.path.join(filepath,os.getenv('BACKUP_APPLICATION_SCOPE_FILE')+'s', filename + ".json")) as json_file:
            json_data = json.load(json_file)

        # Filter Not Required Data
        fileds_to_remove = ["id","name", "created_at", "updated_at", "deleted_at", "dirty", "dirty_short_query"]
        filterItems(json_data, fileds_to_remove)

        # Modify the vrf Data if selected
        if vrf:
            target_vrf=new_vrf["id"]
            json_data["vrf_id"] = target_vrf
            json_data["short_query"] = updateQuery(json_data["short_query"], target_vrf, "vrf_id")
            json_data["query"] = updateQuery(json_data["query"], target_vrf, "vrf_id")
            json_data["root_app_scope_id"] = new_vrf["root_app_scope_id"]

            # when root and parent scope are same
            if json_data["parent_app_scope_id"]== vrf["root_app_scope_id"]:
                json_data["parent_app_scope_id"] = new_vrf["root_app_scope_id"]
            else:
                if not json_data["parent_app_scope_id"] == "":
                    # ignore if parent is empty
                    get_scope_data=self.get_application_scope_leaf(filepath,json_data["parent_app_scope_id"],vrf,new_vrf)
                    if not get_scope_data:
                        logger.error('unable to get or create the scope {}'.format(json_data["parent_app_scope_id"]))
                    else:
                        json_data["parent_app_scope_id"]=get_scope_data.get("id","")

                # loop to create next child if the parent scope is empty
                if json_data["parent_app_scope_id"] == "":
                    for child in json_data["child_app_scope_ids"]:
                        self.create_application_scope_leaf(filepath, child, vrf, new_vrf)


        else:
            if json_data["parent_app_scope_id"] == json_data["root_app_scope_id"]:
                if not json_data["root_app_scope_id"]== json_data["id"]:
                    json_data["root_app_scope_id"]=json_data["root_app_scope_id"]= self.create_application_scope_leaf(filepath,json_data["root_app_scope_id"],vrf,new_vrf)
            elif not json_data["root_app_scope_id"] == json_data["id"]:
                json_data["root_app_scope_id"]= self.create_application_scope_leaf(filepath, json_data["root_app_scope_id"], vrf, new_vrf)
        json_data["child_app_scope_ids"] = []

        resp = self.restclient.post('/app_scopes', json_body=json.dumps(json_data),timeout=self.timeout)
        if resp.status_code==200:
            new_scope=json.loads(resp.text)
            logger.info("Restored Application Scope {},{}".format(filename,new_scope["short_name"]))
            self.write_to_file(os.path.join(filepath, os.getenv('APP_SCOPE_MAPPINGS')),filename,resp.text)
            return new_scope
        else:
            logger.error("Unable to Restore Applicaiton Scope {},{}-{},{}".format(filename,json_data["short_name"],resp.status_code,resp.text ))
            return json.loads(resp.text)

    def create_application_scopes(self, filepath,vrf=None,new_vrf=None):
        # def check_vrf(element):
        #     if element["vrf_id"] == vrf["id"]:
        #         return element
        #
        # def check_root_app_scope_id(element):
        #     if element["root_app_scope_id"]==vrf["root_app_scope_id"]:
        #         return element

        def get_child_count(element):
            return len(element["child_app_scope_ids"])

        with open(os.path.join(filepath,os.getenv('BACKUP_APPLICATION_SCOPE_FILE') + '.json')) as app:
            data = json.load(app)
            total_app_scopes =len(data)
            if vrf:
                # Create Mapping directory if VRF is being used
                os.makedirs(os.path.join(filepath, os.getenv('APP_SCOPE_MAPPINGS')),exist_ok=True)
                app_scope_order_path=os.path.join(filepath,os.getenv('BACKUP_APPLICATION_SCOPE_ORDER_FILE'),str(vrf["root_app_scope_id"])+'.json')

                with open(app_scope_order_path) as fp:
                    data=json.load(fp)
                # # Sort to get Leaf Scope in the List
                # filtered_app_scopes = list(filter(check_vrf, data))
                # filtered_app_scopes.sort(key=get_child_count)
                # total_app_scopes=len(filtered_app_scopes)
                # logger.info('Found {} Application Scope '.format(total_app_scopes))
                #
                # # Restore with Root Scopes first
                # filtered_root_app_scopes = list(filter(check_root_app_scope_id, filtered_app_scopes))
                # for count, app_scope_config in enumerate(filtered_root_app_scopes):
                #     self.create_application_scope_leaf(filepath,app_scope_config["id"],vrf,new_vrf)
                #
                # # Restore Remaining Scope and Write to file for mapping
                # for count, app_scope_config in enumerate(filtered_app_scopes-filtered_root_app_scopes):
                #     self.create_application_scope_leaf(filepath,app_scope_config["id"],vrf,new_vrf)
                # Restore Remaining Scope and Write to file for mapping
                total_app_scopes=len(data)
                # data.sort(key=get_child_count,reverse=True)
                root_scope_data={}
                # Identify the previous root app scope information from list
                for count,app_scope_config in enumerate(data):
                    if app_scope_config["id"]== vrf["root_app_scope_id"]:
                        root_scope_data=app_scope_config
                        break;

                for child in root_scope_data["child_app_scope_ids"]:
                    resp = self.create_application_scope_leaf(filepath, child, vrf, new_vrf)

                for count,app_scope_config in enumerate(data):
                    # create Application Scope
                    resp=self.create_application_scope_leaf(filepath,app_scope_config["id"],vrf,new_vrf)
                    logger.info('Restoring Application Scope {}/{} of {}'.format(count + 1, total_app_scopes,
                                                                                 app_scope_config['name']))

            else:
                for count,app_scope_config in enumerate(data):
                    # req_payload = {
                    #     "id": app_config["id"],
                    #     "app_scope_id": app_config["app_scope_id"],
                    #     "name": app_config["name"],
                    #     "description": app_config["description"],
                    #     "primary": app_config["primary"]
                    # }
                    with open(os.path.join(filepath,os.getenv('BACKUP_APPLICATION_SCOPE_FILE')+'s',app_scope_config["id"]+'.json')) as json_file:
                        json_data=json_file.read()
                    req_payload=json.loads(json_data)

                    logger.debug('Create Application Scope:' + json.dumps(req_payload))

                    resp = self.restclient.post('/app_scopes', json_body=json.dumps(req_payload),timeout=self.timeout)
                    logger.info('Restoring Application Scope {}/{} of {}'.format(count + 1, total_app_scopes, app_scope_config['name']))
                    logger.debug(resp.text)

    def add_user_roles(self, filepath):
        """Add roles."""
        with open(os.path.join(filepath,os.getenv("BACKUP_ROLE_FILE")+'.json')) as app:
            data = json.load(app)
            for role_config in data:
                req_payload = {
                    "id": role_config["id"],
                    "name": role_config["name"],
                    "app_scope_id": role_config["app_scope_id"],
                    "description": role_config["description"],
                }
                logger.debug('User Role :' + json.dumps(req_payload))
                resp = self.restclient.post('/roles', json_body = json.dumps(req_payload),timeout=self.timeout)
                if resp.status_code == 200:
                    logger.info(f'Role {role_config["name"]} successfully added')
                else:
                    logger.error(f'Role {role_config["name"]} not added')

    def add_user_to_role(self, filepath):
        "Add a user to a role"
        # caching Roles details for logging
        with open(os.path.join(filepath,os.getenv("BACKUP_ROLE_FILE")+'.json')) as app:
            role_data = json.load(app)

        # Importing Users Details
        with open(os.path.join(filepath,os.getenv("BACKUP_USER_FILE")+'.json')) as app:
            data = json.load(app)
            for user_config in data:
                for user_role in user_config["role_ids"]:
                    req_payload = {
                        "role_id": user_role
                    }
                    logger.debug('Adding User to Role :'+json.dumps(req_payload))
                    resp = self.restclient.post(f'/users/{user_config["id"]}/add_role',timeout=self.timeout)
                    if resp.status.code == 200:
                        role_details= list(filter(lambda x: ( user_role in x["id"] ), role_data))
                        logger.info("User {} {} successfully assigned role - {}".format(user_config["first_name"],user_config["last_name"],role_details[0]["name"]))
                    else:
                        logger.error("User assignment failed.")

    def add_users(self, filepath):
        "Add Users."
        with open(os.path.join(filepath,os.getenv("BACKUP_USER_FILE")+'.json')) as app:
            data = json.load(app)
            for user_config in data:
                req_payload = {
                    "first_name": user_config["first_name"],
                    "last_name": user_config["last_name"],
                    "email": user_config["email"],
                    "app_scope_id": user_config["app_scope_id"],
                }
                logger.debug('Adding User :' + json.dumps(req_payload))
                resp = self.restclient.post(f'/users', json_body = json.dumps(req_payload),timeout=self.timeout)
                if resp.status_code == 200:
                    logger.info("User added successfully - {} {}".format(user_config["first_name"],user_config["last_name"]))

    def create_inventory_filter(self, filepath,vrf=None,new_vrf=None):
        "Create an inventory filter"
        with open(os.path.join(filepath,os.getenv("BACKUP_INVENTORY_FILTER_FILE")+'.json')) as app:
            data = json.load(app)
            if not vrf:
                for inventory_filter_config in data:
                    req_payload = {
                        "app_scope_id": inventory_filter_config["app_scope_id"],
                        "name": inventory_filter_config["name"],
                        "query": inventory_filter_config["query"]
                    }
                    logger.debug('Adding Inventory Filter:' + json.dumps(req_payload))

                    resp = self.restclient.post('/filters/inventories', json_body=json.dumps(req_payload),timeout=self.timeout)
                    if resp.status_code == 200:
                        logger.info(f'Inventory filter {inventory_filter_config["name"]} added successfully.')
            else:
                # Getting APP Scope Id's from root scopes
                scope_list=[]
                scope_list.append(vrf["root_app_scope_id"])
                with open(os.path.join(filepath, os.getenv("BACKUP_APPLICATION_SCOPE_ORDER_FILE") ,vrf["root_app_scope_id"]+ '.json')) as root_scope:
                    root_scope_data=json.load(root_scope)
                    for scope_data in root_scope_data:
                        scope_list.append(scope_data["id"])

                for inventory_filter_config in data:
                    app_scope_id=inventory_filter_config["app_scope_id"]
                    if app_scope_id in scope_list:
                        new_path_file=os.path.join(filepath,os.getenv("APP_SCOPE_MAPPINGS"),app_scope_id+".json")
                        if app_scope_id == vrf["root_app_scope_id"]:
                            app_scope_id=new_vrf["root_app_scope_id"]
                        elif os.path.os.path.exists(new_path_file):
                            with open(new_path_file) as scope_mapping:
                                map_data=json.load(scope_mapping)
                                app_scope_id=map_data["id"]
                        else:
                            continue
                        req_payload = {
                            "app_scope_id": app_scope_id,
                            "name": inventory_filter_config["name"],
                            "query": updateQuery(inventory_filter_config["query"],new_vrf["id"],"vrf_id"),
                            "primary":inventory_filter_config["primary"],
                            "public":inventory_filter_config["public"]
                        }
                        logger.debug('Adding Inventory Filter:' + json.dumps(req_payload))

                        resp = self.restclient.post('/filters/inventories', json_body=json.dumps(req_payload),
                                                    timeout=self.timeout)
                        if resp.status_code == 200:
                            logger.info(f'Inventory filter {inventory_filter_config["name"]} added successfully.')
                        else:
                            logger.error(f'Failed to create Inventory Filter {inventory_filter_config["id"]}-{inventory_filter_config["name"]},{resp.status_code},{resp.reason} ')
                            logger.debug(
                                f'{inventory_filter_config["id"]}-{inventory_filter_config["name"]},{resp.status_code},{resp.text} ')

    def create_vrf(self, filepath,id=None,target=None):
        "Create a VRF"
        if id:
            with open(os.path.join(filepath,os.getenv("BACKUP_VRF_FILE")+'.json')) as app:
                data = json.load(app)
                def check_id(element):
                    if element["id"]==int(id):
                        return True
                    return False
                vrf_config=list(filter(check_id,data))[0]
            with open(os.path.join(filepath, os.getenv('BACKUP_COLLECTION_FILE'),str(id) + ".json")) as collection_rule_fp:
                collection_rule = collection_rule_fp.read()
                req_payload = {
                    "id": target,
                    # Error getting thrown on tentant_id
                    "tenant_id": vrf_config["tenant_id"],
                    "name": vrf_config["name"],
                    "switch_vrfs": vrf_config["switch_vrfs"],
                    "apply_monitoring_rules": collection_rule
                }

                logger.debug('VRF: ' + json.dumps(req_payload))
                resp = self.restclient.post('/vrfs', json_body=json.dumps(req_payload), timeout=self.timeout)
                if resp.status_code == 200:
                    logger.info(f'VRF {vrf_config["name"]} added successfully.')
                else:
                    logger.error(
                        "VRF Creation Failed {} with Error Code {},{}".format(vrf_config["id"], resp.status_code,
                                                                              resp.reason))
        else:
            with open(os.path.join(filepath,os.getenv("BACKUP_VRF_FILE")+'.json')) as app:
                data = json.load(app)
            for vrf_config in data:
                with open(os.path.join(filepath, os.getenv('BACKUP_COLLECTION_FILE'), vrf_config["id"] +".json")) as collection_rule_fp:
                    collection_rule=collection_rule_fp.read()
                req_payload = {
                    "id": vrf_config["id"],
                    # Error getting thrown on tentant_id
                    # "tenant_id": vrf_config["tenant_id"],
                    "name": vrf_config["name"],
                    "switch_vrfs": vrf_config["switch_vrfs"],
                    "apply_monitoring_rules":collection_rule
                }

                logger.debug('VRF: '+json.dumps(req_payload))
                resp = self.restclient.post('/vrfs', json_body=json.dumps(req_payload),timeout=self.timeout)
                if resp.status_code == 200:
                    logger.info(f'VRF {vrf_config["name"]} added successfully.')
                else:
                    logger.error("VRF Creation Failed {} with Error Code {},{}".format(vrf_config["id"],resp.status_code,resp.reason))

    def get_vrf_from_backup(self,filepath,vrf_id):
        with open(os.path.join(filepath, os.getenv("BACKUP_VRF_FILE") + '.json')) as app:
            data = json.load(app)
            for vrf in data:
                if vrf["id"]==int(vrf_id):
                    return vrf
        return None


    def get_or_create_vrf(self, filepath, vrf_id,new_vrf_id):
        "Create a VRF"
        resp = self.restclient.get('/vrfs', timeout=self.timeout)
        if resp.status_code==200:
            vrf_list=json.loads(resp.text)
            for vrf in vrf_list:
                if vrf["id"]==int(new_vrf_id):
                    logger.info("Found Existing VRF with ID {}".format(new_vrf_id))
                    logger.debug(vrf)
                    return vrf
            # self.create_vrf(filepath,id=int(vrf_id),target=int(new_vrf_id))

            logger.info("VRF with ID {} Not Found".format(new_vrf_id))
        return None

    def delete_application_scopes(self,target_vrf):
        def getPolicyPriority(item):
            return item["policy_priority"]
        app_scope_id=target_vrf["root_app_scope_id"]
        logger.info('Gathering the Scope Order')
        resp=self.restclient.get("/app_scopes/{}/policy_order".format(app_scope_id),timeout=self.timeout)
        if resp.status_code == 200:
            resp_data=json.loads(resp.text)
            logger.info('Sorting Scope Order in reverse based on policy priority')
            resp_data.sort(key=getPolicyPriority,reverse=True)

            for i,scope_data in enumerate(resp_data):
                resp=self.restclient.delete("/app_scopes/{}".format(scope_data["id"]),timeout=self.timeout)
                logger.info('Deleted Scope {}:{}-{},{}'.format(target_vrf["id"],scope_data["id"],scope_data["name"],resp.status_code))


    def restore(self, filepath, modules,vrf,new_vrf):
        resources = modules.split(',')
        logger.debug('Found Resoureces: '+modules)
        # IF VRF is provided
        if vrf:
            processed=[]
            for resource in resources:
                logger.info('Restoring Resource ' + resource)
                if 'application' == resource:
                    processed.append(resource)
                    self.create_application(filepath,vrf,new_vrf)
                if 'application_scope' == resource:
                    processed.append(resource)
                    self.create_application_scopes(filepath,vrf,new_vrf)
                if 'inventory_filter' == resource:
                    processed.append(resource)
                    self.create_inventory_filter(filepath,vrf,new_vrf)
                if 'vrf' == resource:
                    processed.append(resource)
            resources=set(resources)- set(processed)

        for resource in resources:
            logger.info('Restoring Resource '+resource)
            if 'application' == resource:
                self.create_application(filepath)
            if 'application_scope' == resource:
                self.create_application_scopes(filepath)
            if 'user_and_role' == resource:
                self.add_users(filepath)
                self.add_user_roles(filepath)
                self.add_user_to_role(filepath)
            if 'inventory_filter' == resource:
                self.create_inventory_filter(filepath)
            if 'vrf' == resource:
                self.create_vrf(filepath)