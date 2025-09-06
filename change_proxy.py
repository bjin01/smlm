# -*- coding: utf-8 -*-
'''
SUSE Manager - change minion's proxy server
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


log = logging.getLogger("suma_change_proxy")
log.propagate = False
formatter = logging.Formatter('%(asctime)s | %(module)s | %(levelname)s | %(message)s') 

if not any(isinstance(h, logging.StreamHandler) for h in log.handlers):
    streamhandler = logging.StreamHandler()
    streamhandler.setFormatter(formatter)
    log.addHandler(streamhandler)


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
                'servername': suma_server
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


def read_config(config):
    """
    Reads SUSE Manager configuration and logs in, returning (client, key).
    """
    suma_config = _get_suma_configuration(config)
    if not suma_config:
        log.error("Failed to read SUSE Manager configuration.")
        raise RuntimeError("Could not read SUSE Manager configuration.")
    client, key = _get_session(suma_config)
    return client, key

def parse_minion_list(client, key, minion_list_file):
    """
    Parse minion list file and match with active systems in SUSE Manager.
    Returns a list of dictionaries with hostname and system-id for found systems.
    """
    # Read minion list from file
    try:
        with open(minion_list_file, 'r') as file:
            minion_hostnames = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        log.error(f"Minion list file '{minion_list_file}' not found.")
        return []
    except Exception as e:
        log.error(f"Error reading minion list file '{minion_list_file}': {e}")
        return []
    
    if not minion_hostnames:
        log.warning("No minions found in the minion list file.")
        return []
    
    # Get all active systems from SUSE Manager
    try:
        active_systems = client.system.listActiveSystems(key)
    except Exception as e:
        log.error(f"Error retrieving active systems from SUSE Manager: {e}")
        return []
    
    # Match minions with active systems
    found_minions = []
    not_found_minions = []
    
    for hostname in minion_hostnames:
        found = False
        for system in active_systems:
            # Check if hostname matches system name
            if system.get('name', '').lower() == hostname.lower():
                found_minions.append({
                    'hostname': hostname,
                    'system_id': system.get('id')
                })
                log.info(f"Found minion '{hostname}' with system ID: {system.get('id')}")
                found = True
                break
        
        if not found:
            not_found_minions.append(hostname)
            log.warning(f"Minion '{hostname}' not found in active systems.")
    
    # Log summary of not found minions
    if not_found_minions:
        log.error(f"The following {len(not_found_minions)} minions were not found in SUSE Manager:")
        for minion in not_found_minions:
            log.error(f"  - {minion}")
    
    log.info(f"Found {len(found_minions)} out of {len(minion_hostnames)} minions in SUSE Manager.")
    return found_minions

def verify_proxy(client, key, move_to_proxy):
    """
    Verify that the specified proxy server exists in SUSE Manager.
    Returns True if proxy is found, False otherwise.
    """
    if not move_to_proxy or not move_to_proxy.strip():
        log.error("No proxy server specified for verification.")
        return False
    
    try:
        # Get list of all proxies from SUSE Manager
        proxies = client.proxy.listProxies(key)
    except Exception as e:
        log.error(f"Error retrieving proxy list from SUSE Manager: {e}")
        return False
    
    # Search for the specified proxy
    for proxy in proxies:
        proxy_name = proxy.get('name', '')
        if proxy_name.lower() == move_to_proxy.lower():
            log.info(f"Proxy server '{move_to_proxy}' found with system ID: {proxy.get('id')}")
            return True
    
    log.error(f"Proxy server '{move_to_proxy}' not found in SUSE Manager.")
    log.info("Available proxies:")
    for proxy in proxies:
        log.info(f"  - {proxy.get('name', 'Unknown')} (ID: {proxy.get('id', 'Unknown')})")
    
    return False

def verify_minions(client, key, list_of_minions, move_to_proxy):
    """
    Verify minions and filter out those already connected to the target proxy.
    Returns a list of qualified minions that need proxy change.
    """
    if not list_of_minions:
        log.warning("No minions provided for verification.")
        return []
    
    qualified_minions = []
    already_connected = []
    
    for minion in list_of_minions:
        system_id = minion.get('system_id')
        hostname = minion.get('hostname')
        
        if not system_id:
            log.warning(f"Skipping minion '{hostname}' - no system ID available.")
            continue
        
        try:
            # Get connection path for the system
            connection_path = client.system.getConnectionPath(key, system_id)
            
            # Check if the system is already connected through the target proxy
            current_proxy = None
            if connection_path and len(connection_path) > 0:
                # Find the proxy at position 1 (direct proxy that system connects to)
                for proxy in connection_path:
                    if proxy.get('position') == 1:
                        current_proxy = proxy.get('hostname', '')
                        break
            
            if current_proxy and current_proxy.lower() == move_to_proxy.lower():
                already_connected.append(hostname)
                log.info(f"Minion '{hostname}' is already connected through proxy '{move_to_proxy}'. Skipping.")
            else:
                qualified_minions.append(minion)
                if current_proxy:
                    log.info(f"Minion '{hostname}' currently connected through proxy '{current_proxy}'. Needs change to '{move_to_proxy}'.")
                else:
                    log.info(f"Minion '{hostname}' not connected through any proxy. Will be connected to '{move_to_proxy}'.")
                    
        except Exception as e:
            log.error(f"Error getting connection path for minion '{hostname}' (ID: {system_id}): {e}")
            # Add to qualified list if we can't determine current connection
            qualified_minions.append(minion)
    
    # Log summary
    if already_connected:
        log.info(f"The following {len(already_connected)} minions are already connected to proxy '{move_to_proxy}':")
        for minion in already_connected:
            log.info(f"  - {minion}")
    
    log.info(f"Qualified {len(qualified_minions)} out of {len(list_of_minions)} minions for proxy change.")
    return qualified_minions

def change_proxy(client, key, qualified_minions, move_to_proxy):
    """
    Change the proxy for qualified minions using the system.changeProxy API.
    """
    if not qualified_minions:
        log.warning("No qualified minions to change proxy for.")
        return True
    
    # First, get the proxy ID for the target proxy
    proxy_id = None
    try:
        proxies = client.proxy.listProxies(key)
        for proxy in proxies:
            if proxy.get('name', '').lower() == move_to_proxy.lower():
                proxy_id = proxy.get('id')
                break
    except Exception as e:
        log.error(f"Error retrieving proxy list to get proxy ID: {e}")
        return False
    
    if not proxy_id:
        log.error(f"Could not find proxy ID for '{move_to_proxy}'.")
        return False
    
    log.info(f"Using proxy ID {proxy_id} for proxy '{move_to_proxy}'.")
    
    # Prepare list of system IDs
    system_ids = []
    minion_map = {}  # Map system_id to hostname for logging
    
    for minion in qualified_minions:
        system_id = minion.get('system_id')
        hostname = minion.get('hostname')
        if system_id:
            system_ids.append(system_id)
            minion_map[system_id] = hostname
    
    if not system_ids:
        log.warning("No valid system IDs found in qualified minions.")
        return True
    
    log.info(f"Changing proxy for {len(system_ids)} minions to '{move_to_proxy}'...")
    
    try:
        # Use system.changeProxy API with list of system IDs
        action_ids = client.system.changeProxy(key, system_ids, proxy_id)
        
        if action_ids:
            log.info(f"Proxy change operation initiated successfully. Action IDs: {action_ids}")
            log.info("Successfully initiated proxy change for the following minions:")
            for system_id in system_ids:
                hostname = minion_map.get(system_id, f"Unknown (ID: {system_id})")
                log.info(f"  - {hostname}")
            return True
        else:
            log.error("Proxy change operation failed - no action IDs returned.")
            return False
            
    except Exception as e:
        log.error(f"Error changing proxy for minions: {e}")
        log.error("Failed to change proxy for the following minions:")
        for system_id in system_ids:
            hostname = minion_map.get(system_id, f"Unknown (ID: {system_id})")
            log.error(f"  - {hostname}")
        return False

def change_minion_proxy(config, minion_list, move_to_proxy, **kwargs):
    client, key = read_config(config)
    
    if not verify_proxy(client, key, move_to_proxy):
        log.error(f"Cannot proceed with changing proxy. Proxy '{move_to_proxy}' verification failed.")
        return False

    list_of_minions = parse_minion_list(client, key, minion_list)
    qualified_minions = verify_minions(client, key, list_of_minions, move_to_proxy)
    change_proxy(client, key, qualified_minions, move_to_proxy)

    return True
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Change minion's proxy server.")
    parser.add_argument("--config", default="suma_config.yaml", help="Path to config file")
    parser.add_argument("--minion_list", default="minion_list.txt", help="Path to minion list file")
    parser.add_argument("--move_to_proxy", default="", help="provide the new proxy server")
    parser.add_argument("params", nargs=argparse.REMAINDER, help="Additional key=value parameters")

    args = parser.parse_args()

    kwargs = {}
    for param in args.params:
        if '=' in param:
            key, value = param.split('=', 1)
            kwargs[key] = value

    if args.move_to_proxy and len(args.move_to_proxy) > 0:
        change_minion_proxy(args.config, args.minion_list, args.move_to_proxy, **kwargs)
    else:
        log.error("No new proxy server specified.")