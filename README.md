# gve_devnet_secure_workload_configuration_automation_script
An python Script by which we can take backup of existing application data and configuration from secure workload and to restore it back via help of api.


## Contacts
* Lakshya Tyagi
*  Raveesh Malyavantham V

## Solution Components
* Cisco Secure Workload (Tetration)
*  Python

## Related Sandbox Environment
This is as a template, project owner to update

## Installation/Configuration

Setting up virtual environment
```python
# creating virtual environment
python -m venv venv
source venv/bin/activate

# Dependency or requirement installation
pip install -r requirements.txt
```

Update Tetration Details in the **.env** file

```python
# Add any settings in environemnt fields or files.  Below is an example:
# Open API enabled Tetration Instance details
TETRATION_URL= https://<tetration_url>
TETRATION_APP_KEY= 
TETRATION_APP_SECRET=
```

To enable debug mode in logging
```python
# change logger level to DEBUG instead of INFO in conf/logger.conf file
[logger_root]
level=INFO

#and
[handler_fileHandler]
level=INFO
```


## Usage

This is a template, project owner to update

Add any steps needed for someone to run your project.
The following options can be used
```commandline
# refer BACKUP_ALL in .env file
-a allresources 
-m specified resource eg: "resource1,resource2,...resourceN"
```
To run the backup  
``` python backup.py ```  
or  
``` python backup.py -a ```

To Restore the existing backup
The following options can be used
```commandline
-t tarfile
-d directory

# refer RESTORE_ALL in .env file
-a allresources
-m specified resource eg: "resource1,resource2,...resourceN"
```
```python restoration.py -t <tar.gz file with path>```  
or   
```python restoration.py -d <backup path> ```

# Screenshots

![/IMAGES/0image.png](/IMAGES/0image.png)

### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.