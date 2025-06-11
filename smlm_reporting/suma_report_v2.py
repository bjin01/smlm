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
import html
import six
from datetime import datetime,  timedelta
from contextlib import contextmanager

from typing import Any, TYPE_CHECKING
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


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

def _decrypt_password(password_encrypted, suma_key_file="suma_key.yaml"):
    
    encrypted_pwd = ""
    if not os.path.exists(suma_key_file):
        log.error("No suma_key.yaml found")
        if os.environ.get('SUMAKEY') == None: 
            log.fatal("You also don't have ENV SUMAKEY set. Use unencrypted pwd.")
            return str(password_encrypted)
        else:
            
            encrypted_pwd = os.environ.get('SUMAKEY')
    else:
        
        with open(suma_key_file, 'r') as file:
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
            password = _decrypt_password(password_encrypted, suma_config.get('suma_key_file', ""))
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
                'email_subject': suma_config.get('email_subject', "subject"),
                'pre_html_file': suma_config.get('pre_html_file', ""),
                'post_html_file': suma_config.get('post_html_file', "")

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

def get_patches_by_advisory_type(client, key, systemname, systemid, advisory_type):
    try:
        getRelevantErrataByType_result = client.system.getRelevantErrataByType(key, systemid, advisory_type)
    except Exception as exc:
        err_msg = 'Exception raised while get system.getRelevantErrataByType for {}: {}'.format(systemname, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    errata_result = {}

    internal_type = ""
    if "security" in str(advisory_type).lower():
        internal_type = "Security Advisory"
    
    if "bug" in str(advisory_type).lower():
        internal_type = "Bug Fix Advisory"
    
    if "enhancement" in str(advisory_type).lower():
        internal_type = "Product Enhancement Advisory"
    
    if internal_type == "":
        err_msg = f"No matching advisory_type found in security, bug nor enhancement. Value given: {advisory_type}"
        log.error(err_msg)
        return {'Error': err_msg}
    
    errata_result[internal_type] = 0

    if len(getRelevantErrataByType_result) > 0:
        
        errata_result.update({internal_type: int(len(getRelevantErrataByType_result))})
        return errata_result
    else:
        return errata_result
    
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
        err_msg = 'Exception raised while get systemgroup.listSystemsMinimal: {0}'.format(exc)
        log.error(err_msg)
        return {"Error": exc}
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
    
def get_patches_all_advisory_type(client, key, systemname, systemid):
    security_types = ["Security Advisory", "Bug Fix Advisory", "Product Enhancement Advisory"]
    errata_result = {}

    for s_type in security_types:
        errata_result[s_type] = 0
        try:
            getRelevantErrataByType_result = client.system.getRelevantErrataByType(key, systemid, s_type)
            #print("getRelevantErrataByType_result {} {}".format(s_type, len(getRelevantErrataByType_result)))
        except Exception as exc:
            err_msg = 'Exception raised while get system.getRelevantErrataByType in get_patches_all_advisory_type for {}: {}'.format(systemname, exc)
            log.error(err_msg)
            return {'Error': err_msg}
        
        if len(getRelevantErrataByType_result) > 0:
            errata_result.update({s_type: int(len(getRelevantErrataByType_result))})
    
    return errata_result

def write_html(suma_config_file, output_html_file, pre_html_file, post_html_file, final_result, groups=[]):
    color_threshold = 10
    rows = {
        "col1": {"key_name": "name", "column_name": "Hostname"},
        "col2": {"key_name": "base_product", "column_name": "OS"},
        "col3": {"key_name": "groups", "column_name": "Gruppe(n)"},
        "col4": {"key_name": "kernel", "column_name": "Kernel"},
        "col5": {"key_name": "outdated_pkg_count", "column_name": "offene Updates"},
        "col6": {"key_name": "Security Advisory", "column_name": "Security Updates"},
        "col7": {"key_name": "Bug Fix Advisory", "column_name": "Bugfix Updates"},
        "col8": {"key_name": "Product Enhancement Advisory", "column_name": "Enhancement Updates"},
        "col9": {"key_name": "extra_pkg_count", "column_name": "Nicht compliant Pakete"},
        "col10": {"key_name": "last_boot", "column_name": "Letzter Reboot"},
    }
    suma_config = _get_suma_configuration(suma_config_file)
    server = suma_config["servername"]
    url_system = f"https://{server}/rhn/systems/details/Overview.do?sid="

    if len(groups) > 0:
        url_text = []
        url = f"https://{server}/rhn/groups/ListRemoveSystems.do?sgid="
        for g in groups:
            if g['id'] != 0:
                url_text.append(f"<p>Gruppe: <a href='{url}{g['id']}' style='text-decoration:none; color:blue;'>{g['name']}</a> Anmerkung: {g['comment']}</p>")
            else:
                log.info("g['comment']: {}".format(g['comment']))
                
                url_text.append(f"<p>Gruppe: {g['name']} Anmerkung: {html.escape(str(g['comment']))}</p>")

    try:
        with open(output_html_file, 'w') as param_file:
            param_file.write("<html><head><title>SUMA Report</title></head><body>")
            if pre_html_file and os.path.exists(pre_html_file):
                try:
                    with open(pre_html_file, 'r') as pre_file:
                        pre_content = pre_file.read()
                        param_file.write(pre_content)
                except Exception as e:
                    log.error(f"Failed to read pre_html_file: {e}")

            if suma_config.get("email_recipients"):
                param_file.write("<h4>Email gesendet an:</h4>")
                param_file.write("<ul>")
                for recipient in suma_config["email_recipients"]:
                    param_file.write(f"<li>{html.escape(recipient)}</li>")
                param_file.write("</ul>")

            param_file.write("<h1>SUMA Report</h1>")

            if len(groups) > 0:
                for url_text_line in url_text:
                    #print(url_text_line)
                    param_file.write(url_text_line)

            param_file.write("<table border='1'>")
            param_file.write("<tr>")

            for key in rows.values():
                key_name = key.get("key_name")
                col_name = key.get("column_name")
                if key_name in final_result[0].keys():
                    param_file.write(f"<th>{col_name}</th>")
            param_file.write("</tr>")

            for row in final_result:
                
                param_file.write("<tr>")
                for key in rows.values():
                    
                    k_name = key.get("key_name")
                    if k_name in row.keys():
                        if k_name == "name":
                            param_file.write(f"<td><a href='{url_system}{row.get('id', '')}' style='text-decoration:none; color:blue;'>{html.escape(row.get(k_name, ''))}</a></td>")
                            
                        elif k_name in ["outdated_pkg_count", "extra_pkg_count"] and row.get(k_name, 0) > color_threshold:
                            param_file.write(f"<td style='color:red;'>{row.get(k_name, '')}</td>")
                        elif k_name in ["Security Advisory", "bugfix_patches"] and row.get(k_name, 0) > color_threshold:
                            param_file.write(f"<td style='color:red;'>{row.get(k_name, '')}</td>")
                        else:
                            param_file.write(f"<td>{row.get(k_name, '')}</td>")
                param_file.write("</tr>")
            param_file.write("</table>")
            if post_html_file and os.path.exists(post_html_file):
                try:
                    with open(post_html_file, 'r') as post_file:
                        post_content = post_file.read()
                        param_file.write(post_content)
                except Exception as e:
                    log.error(f"Failed to read post_html_file: {e}")
            param_file.write("</body></html>")
        log.info(f"final result written to {output_html_file}")
    except Exception as e:
        log.error(f"Failed to write final result to file: {e}")


def send_email(smtp_server, smtp_port, email_from, sender_password, email_recipients, email_subject, attachment_path):

    try:
        # Create the email
        msg = MIMEMultipart()
        msg['From'] = email_from
        if isinstance(email_recipients, list):
            msg['To'] = ", ".join(email_recipients)
        else:
            msg['To'] = email_recipients
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

        log.info(f"Email sent successfully to {email_recipients}")
    except Exception as e:
        log.error(f"Failed to send email: {e}")
    
def last_rebooted(client, key, systemname):
    try:
        getId_result = client.system.getId(key, systemname)
        system_details = client.system.getDetails(key, getId_result[0]["id"])
    except Exception as exc:
        err_msg = 'Exception raised while get getId or getDetails: {0}'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    if isinstance(system_details, dict):
            last_boot = ""
            if "last_boot" in system_details.keys():      
                if system_details["last_boot"]:
                    if isinstance(system_details["last_boot"], datetime):
                        last_boot = system_details["last_boot"].strftime("%d.%m.%Y %H:%M")
                        return {"last_boot": last_boot}
                    else:
                        last_boot = system_details["last_boot"]
                        return {"last_boot": last_boot}
    return {"last_boot": ""}

def get_groupid(client, key, groupname):
    try:
        groupdetails_result = client.systemgroup.getDetails(key, groupname)
        return groupdetails_result["id"]
    except Exception as exc:
        err_msg = 'Exception raised while get systemgroup.getDetails: {0}'.format(exc)
        log.error(err_msg)
        return {'Error': exc}
    return

def run_by_group(suma_config_file, output_html_file, groups, **kwargs):
    suma_config = _get_suma_configuration(suma_config_file)
    server = suma_config["servername"]

    advisory_type = ""

    if 'log_level' in kwargs:
        set_log_level(kwargs["log_level"])
    else:
        log.setLevel(logging.INFO)

    if "advisory_type" in kwargs:
        advisory_type = kwargs["advisory_type"]

    if isinstance(groups, str):
        list_groups = [group.strip() for group in groups.split(",")]
    else:
        list_groups = groups
    final_result = []
    try:
        client, key = _get_session(suma_config)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    groups_data = []

    for groupname in list_groups:
        group_id = get_groupid(client, key, groupname)
        if isinstance(group_id, dict):
            #print("Group: {} {}".format(groupname, group_id["Error"]))
            if "Error" in group_id.keys():
                groups_data.append({"name": groupname, "id": 0, "comment": group_id["Error"]})
                continue

        listSystems_result = get_systems_by_group(client, key, groupname)

        if len(listSystems_result) > 0:
            len_systems = len(listSystems_result)
            groups_data.append({"name": groupname, "id": group_id, "comment": f"{len_systems} Systeme"})
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
        else:
            groups_data.append({"name": groupname, "id": group_id, "comment": "kein System in der Gruppe."})
    
    write_html(
        suma_config_file, 
        output_html_file, 
        suma_config.get("pre_html_file", ""),
        suma_config.get("post_html_file", ""), 
        final_result, groups=groups_data
    )

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

def run_all(suma_config_file, output_html_file="report.html", **kwargs):
    final_result = []
    suma_config = _get_suma_configuration(suma_config_file)
    server = suma_config["servername"]
    ret = dict()
    ret["job_IDs"] = []
    

    if 'log_level' in kwargs:
        set_log_level(kwargs["log_level"])
    else:
        log.setLevel(logging.INFO)
    
    advisory_type = ""

    if "advisory_type" in kwargs:
        advisory_type = kwargs["advisory_type"]

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

                if advisory_type != "":
                    patches_by_advisory_type = get_patches_by_advisory_type(client, key, system["name"], system["id"], advisory_type)
                    system_dict.update(patches_by_advisory_type)
                else:
                    patches_by_advisory_type = get_patches_all_advisory_type(client, key, system["name"], system["id"])
                    system_dict.update(patches_by_advisory_type)

                final_result.append(system_dict)
    
    write_html(
        suma_config_file, 
        output_html_file, 
        suma_config.get("pre_html_file", ""),
        suma_config.get("post_html_file", ""), 
        final_result,
        )
    
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
    parser.add_argument("--groups", nargs='+', help="List of group names to include in the report")
    parser.add_argument("params", nargs=argparse.REMAINDER, help="Additional key=value parameters")

    args = parser.parse_args()

    kwargs = {}
    for param in args.params:
        if '=' in param:
            key, value = param.split('=', 1)
            kwargs[key] = value
    
    if args.groups and len(args.groups) > 0:
        run_by_group(args.config, args.output_html_file, args.groups, **kwargs)
    else:
        run_all(args.config, output_html_file=args.output_html_file, **kwargs)

    