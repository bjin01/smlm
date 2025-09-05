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