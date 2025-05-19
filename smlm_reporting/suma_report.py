# -*- coding: utf-8 -*-
'''
SUSE Manager Reporting in HTML and send Email
================

..

A script to interact with SUSE Manager using xmlrpc API

'''
from __future__ import absolute_import, print_function, unicode_literals
from cryptography.fernet import Fernet
# Import python libs
import atexit
import argparse
import logging
import os
import yaml
import json
import salt.client
import six
from datetime import datetime,  timedelta
from contextlib import contextmanager

try:
    import psycopg2 
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

from typing import Any, TYPE_CHECKING
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None


log = logging.getLogger("suma_report")
log.propagate = False
formatter = logging.Formatter('%(asctime)s | %(module)s | %(levelname)s | %(message)s') 

if not any(isinstance(h, logging.StreamHandler) for h in log.handlers):
    streamhandler = logging.StreamHandler()
    streamhandler.setFormatter(formatter)
    log.addHandler(streamhandler)

if not any(isinstance(h, logging.FileHandler) for h in log.handlers):
    file_handler = logging.FileHandler('/var/log/suma/reporting.log')
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)

_sessions = {}

def set_log_level(log_level):
    """Set the log level globally for the logger."""
    if log_level.upper() == "DEBUG":
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

def _decrypt_password(password_encrypted):
    
    encrypted_pwd = ""
    if not os.path.exists("suma_key.yaml"):
        log.error("No suma_key.yaml found")
        if os.environ.get('SUMAKEY') == None: 
            log.fatal("You also don't have ENV SUMAKEY set. Use unencrypted pwd.")
            return str(password_encrypted)
        else:
            
            encrypted_pwd = os.environ.get('SUMAKEY')
    else:
        
        with open("suma_key.yaml", 'r') as file:
            sumakey_dict = yaml.safe_load(file)
            encrypted_pwd = sumakey_dict["SUMAKEY"]

    if not encrypted_pwd == "":
        saltkey = bytes(str(encrypted_pwd), encoding='utf-8')
        fernet = Fernet(saltkey)
        encmessage = bytes(str(password_encrypted), encoding='utf-8')
        pwd = fernet.decrypt(encmessage)
    else:
        log.fatal("encrypted_pwd is empty. Use unencrypted pwd.")
        return str(password_encrypted)        
    
    return pwd.decode()

def _get_suma_configuration(suma_config_file="suma_config.yaml"):
    '''
    Return the configuration read from the configuration
    file or directory
    '''

    try:
        with open(suma_config_file, 'r') as file:
            suma_config = yaml.safe_load(file)
            if not suma_config:
                suma_config = {}
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file '{suma_config_file}' not found.")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML file '{suma_config_file}': {e}")

    if suma_config:
        try:
            suma_server = suma_config.get('suma_server', "localhost")
            username = suma_config.get('suma_api_username', None)
            password_encrypted = suma_config.get('suma_api_password', None)
            password = _decrypt_password(password_encrypted)
            protocol = suma_config.get('protocol', 'https')
            


            if not username or not password:
                log.error(
                    'Username or Password has not been specified in the master '
                    'configuration for %s', suma_server
                )
                return False

            ret = {
                'api_url': '{0}://{1}/rpc/api'.format(protocol, suma_server),
                'username': username,
                'password': password,
                'servername': suma_server,
                'smtp_server': suma_config.get('smtp_server', "localhost"),
                'smtp_port': int(suma_config.get('smtp_port', 25)),
                'email_from': suma_config.get('email_from', "suma_report"),
                'sender_password': suma_config.get('sender_password', ""),
                'email_recipients': suma_config.get('email_recipients', []),
                'email_subject': suma_config.get('email_subject', "subject")
            }
            return ret
        except Exception as exc:  # pylint: disable=broad-except
            log.error('Exception encountered: %s', exc)
            return False

    return False


def _get_client_and_key(url, user, password, verbose=0):
    '''
    Return the client object and session key for the client
    '''
    session = {}
    session['client'] = six.moves.xmlrpc_client.Server(url, verbose=verbose, use_datetime=True)

    session['key'] = session['client'].auth.login(user, password)
    return session


def _disconnect_session(session):
    '''
    Disconnect API connection
    '''
    session['client'].auth.logout(session['key'])


def _get_session(suma_config):
    '''
    Get session and key
    '''
    server = suma_config["servername"]
    if server in _sessions:
        return _sessions[server]

    session = _get_client_and_key(suma_config['api_url'], suma_config['username'], suma_config['password'])
    atexit.register(_disconnect_session, session)

    client = session['client']
    key = session['key']
    _sessions[server] = (client, key)

    return client, key

def getOutstandingPackages(client, key, systemname, systemid):
    try:
        getId_result = client.system.getId(key, systemname)
    except Exception as exc:
        err_msg = 'Exception raised while get getId: {0}'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}
    pkg_result = {}
    pkg_result["outdated_pkg_count"] = 0
    pkg_result["extra_pkg_count"] = 0

    if len(getId_result) == 1:
        for result in getId_result:
            
            if int(result["id"]) == systemid:
                if "outdated_pkg_count" in result.keys():
                    pkg_result.update({"outdated_pkg_count": int(result["outdated_pkg_count"])})
                else:
                    pkg_result.update({"outdated_pkg_count": 0})
                
                if "extra_pkg_count" in result.keys():
                    pkg_result.update({"extra_pkg_count": int(result["extra_pkg_count"])})
                else:
                    pkg_result.update({"extra_pkg_count": 0})
                    
                return pkg_result
    else:
        log.error("found multiple systemids in resgetOutstandingPackages for {}".format(systemname))
        return pkg_result

def getkernel(client, key, systemid):
    try:
        getRunningKernel_result = client.system.getRunningKernel(key, systemid)
        return {"kernel": getRunningKernel_result}
    except Exception as exc:
        err_msg = 'Exception raised while get getRunningKernel: {0}'.format(exc)
        log.error(err_msg)
        return {'kernel': err_msg}
    return 

def getproduct(client, key, systemid):
    try:
        getInstalledProducts_result = client.system.getInstalledProducts(key, systemid)
    except Exception as exc:
        err_msg = 'Exception raised while get getInstalledProducts: {0}'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}

    if len(getInstalledProducts_result) > 0:
        for product in getInstalledProducts_result:
            for h, v in product.items():
                if product["isBaseProduct"]:
                    if "friendlyName" in product.keys() and product["friendlyName"] != "":
                        product_name = product["friendlyName"]
                    else:
                        product_name = product["name"]
                    return {"base_product": product_name}
    return {"base_product": ""}

def get_systems_by_group(client, key, groupname):
    try:
        listSystemsMinimal_result = client.systemgroup.listSystemsMinimal(key, groupname)
        return listSystemsMinimal_result
    except Exception as exc:
        err_msg = 'Exception raised while get listSystemsMinimal: {0}'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}
    return 

def get_groups_from_system(client, key, systemid):
    groups_string = ""
    try:
        listGroups_result = client.system.listGroups(key, systemid)
        if len(listGroups_result) > 0:
            for group in listGroups_result:
                if int(group["subscribed"]) == 1:
                    g_name = group["system_group_name"]
                    groups_string += f"{g_name}\n"
            return {"groups": groups_string}
    except Exception as exc:
        err_msg = 'Exception raised while get listSystemsMinimal: {0}'.format(exc)
        log.error(err_msg)
        return {'groups': groups_string}
    

def write_html(output_html_file, final_result):
    color_threshold = 10
    rows = {
        "col1": {"key_name": "name", "column_name": "Hostname"},
        "col2": {"key_name": "base_product", "column_name": "OS"},
        "col3": {"key_name": "groups", "column_name": "Gruppe(n)"},
        "col4": {"key_name": "kernel", "column_name": "Kernel"},
        "col5": {"key_name": "outdated_pkg_count", "column_name": "offene Updates"},
        "col6": {"key_name": "extra_pkg_count", "column_name": "Nicht compliant Pakete"},
        "col7": {"key_name": "last_boot", "column_name": "Letzter Reboot"},
    }
    try:
        with open(output_html_file, 'w') as param_file:
            param_file.write("<html><head><title>SUMA Report</title></head><body>")
            param_file.write("<h1>SUMA Report</h1>")
            param_file.write("<table border='1'>")
            param_file.write("<tr>")

            for key in rows.values():
                col_name = key.get("column_name")
                param_file.write(f"<th>{col_name}</th>")
            param_file.write("</tr>")

            for row in final_result:
                param_file.write("<tr>")
                for key in rows.values():
                    k_name = key.get("key_name")
                    if k_name in ["outdated_pkg_count", "extra_pkg_count"] and isinstance(row.get(k_name, 0), int) and row.get(k_name, 0) > color_threshold:
                        param_file.write(f"<td style='color:red;'>{row.get(k_name, '')}</td>")
                    else:
                        param_file.write(f"<td>{row.get(k_name, '')}</td>")
                param_file.write("</tr>")
            param_file.write("</table>")
            param_file.write("</body></html>")
        log.info(f"final result written to {output_html_file}")
    except Exception as e:
        log.error(f"Failed to write final result to file: {e}")


def send_email(smtp_server, smtp_port, email_from, sender_password, email_recipients, email_subject, attachment_path):

    if isinstance(email_recipients, list):
        recipient_email = " ".join(email_recipients)
    try:
        # Create the email
        msg = MIMEMultipart()
        msg['From'] = email_from
        msg['To'] = recipient_email
        msg['Subject'] = email_subject

        # Attach the file
        with open(attachment_path, 'r') as attachment:
            html_content = attachment.read()
            msg.attach(MIMEText(html_content, 'html'))
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
            msg.attach(part)

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if server.has_extn('STARTTLS'):
                server.starttls()
            if sender_password != "":
                server.login(email_from, sender_password)
            server.send_message(msg)

        log.info(f"Email sent successfully to {recipient_email}")
    except Exception as e:
        log.error(f"Failed to send email: {e}")
    
def last_rebooted(client, key, systemname):
    try:
        getId_result = client.system.getId(key, systemname)
    except Exception as exc:
        err_msg = 'Exception raised while get getId: {0}'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    if len(getId_result) == 1:
        if isinstance(getId_result[0], dict):
            last_boot = ""
            if "last_boot" in getId_result[0].keys():
                if getId_result[0]["last_boot"]:
                    if isinstance(getId_result[0]["last_boot"], datetime):
                        last_boot = getId_result[0]["last_boot"].strftime("%d.%m.%Y %H:%M")
                        return {"last_boot": last_boot}
                    else:
                        last_boot = getId_result[0]["last_boot"]
                        return {"last_boot": last_boot}
    return {"last_boot": ""}

def run_by_group(output_html_file, groups, **kwargs):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    if isinstance(groups, str):
        list_groups = [group.strip() for group in groups.split(",")]
    final_result = []
    try:
        client, key = _get_session(suma_config)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    for groupname in list_groups:
        listSystems_result = get_systems_by_group(client, key, groupname)

        if len(listSystems_result) > 0:
            for system in listSystems_result:
                if isinstance(system, dict):
                    system_dict = {
                        "id": system["id"],
                        "name": system["name"],
                        "groups": groupname
                        }
                    
                    base_product = getproduct(client, key, system["id"])
                    system_dict.update(base_product)

                    pkg_info = getOutstandingPackages(client, key, system["name"], system["id"])
                    system_dict.update(pkg_info)

                    kernel_info = getkernel(client, key, system["id"])
                    system_dict.update(kernel_info)

                    last_boot = last_rebooted(client, key, system["name"])
                    system_dict.update(last_boot)

                    final_result.append(system_dict)
    

    write_html(output_html_file, final_result)

    send_email(
        suma_config["smtp_server"],
        suma_config["smtp_port"],
        suma_config["email_from"],
        suma_config["sender_password"],
        suma_config["email_recipients"],
        suma_config["email_subject"],
        output_html_file,
    )
    return

def run_all(output_html_file="report.html", **kwargs):
    final_result = []
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["job_IDs"] = []
    

    if 'log_level' in kwargs:
        set_log_level(kwargs["log_level"])
    else:
        log.setLevel(logging.INFO)
    
    try:
        client, key = _get_session(suma_config)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    try:
        listSystems_result = client.system.listSystems(key)
    except Exception as exc:
        err_msg = 'Exception raised while get listSystems: {0}'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}

    if len(listSystems_result) > 0:
        for system in listSystems_result:
            if isinstance(system, dict):
                last_boot = ""
                if "last_boot" in system.keys():
                    if system["last_boot"]:
                        if isinstance(system["last_boot"], datetime):
                            last_boot = system["last_boot"].strftime("%d.%m.%Y %H:%M")
                        else:
                            last_boot = system["last_boot"]

                
                system_dict = {"id": system["id"],
                               "name": system["name"],
                               "last_boot": last_boot}
                
                base_product = getproduct(client, key, system["id"])
                system_dict.update(base_product)

                pkg_info = getOutstandingPackages(client, key, system["name"], system["id"])
                system_dict.update(pkg_info)

                kernel_info = getkernel(client, key, system["id"])
                system_dict.update(kernel_info)

                system_groups = get_groups_from_system(client, key, system["id"])
                system_dict.update(system_groups)

                final_result.append(system_dict)
    
    write_html(output_html_file, final_result)
    send_email(
        suma_config["smtp_server"],
        suma_config["smtp_port"],
        suma_config["email_from"],
        suma_config["sender_password"],
        suma_config["email_recipients"],
        suma_config["email_subject"],
        output_html_file,
    )
    return
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SUSE Manager Report Generating.")
    parser.add_argument("--config", default="suma_config.yaml", help="Path to config file")
    parser.add_argument("--output-html-file", default="report.html", help="Path to output HTML report")
    parser.add_argument("params", nargs=argparse.REMAINDER, help="Additional key=value parameters")

    args = parser.parse_args()

    kwargs = {}
    for param in args.params:
        if '=' in param:
            key, value = param.split('=', 1)
            kwargs[key] = value
    
    if "groups" in kwargs.keys() and kwargs["groups"] != "":
        groups = kwargs.pop("groups")
        run_by_group(args.output_html_file, groups, **kwargs)
    else:
        run_all(output_html_file=args.output_html_file, **kwargs)

    