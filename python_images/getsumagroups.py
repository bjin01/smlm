import logging
import yaml
log = logging.getLogger(__name__)

def get_external_pillar_dictionary(minion_id, pillar_file='/srv/pillar/sumagroups/init.sls'):
    '''
    This function is used to get the external pillar data from the pillar file.
    '''
    external_pillar_dictionary = {}

    # Get the external pillar data from the pillar file
    try:
        with open(pillar_file, 'r') as f:
            pillar_data = yaml.safe_load(f)
    except Exception as e:
        log.error("Error getting external pillar data: %s", e)

    #log.debug("-----------------Pillar data: %s", pillar_data)

    if isinstance(pillar_data, dict):
        for sumagroup_key, value in pillar_data.items():
            external_pillar_dictionary[sumagroup_key] = []
            #log.debug("------------------Sumagroup key: %s, Value: %s, instance: %s", sumagroup_key, value, isinstance(value, dict))
            if isinstance(value, dict):
                for key, val in value.items():
                    #log.debug("------------------Key: %s, Value: %s", key, val)
                    if minion_id in val:
                        external_pillar_dictionary[sumagroup_key].append(key)
    log.debug("-----------------External pillar dictionary: %s", external_pillar_dictionary)
    return external_pillar_dictionary

def ext_pillar(minion_id, pillar, *args, **kwargs):

    my_pillar = dict()

    if "pillar_file" in kwargs:
        pillar_file = kwargs["pillar_file"]
        log.debug("Pillar file specified: %s", pillar_file)
        my_pillar = get_external_pillar_dictionary(minion_id, pillar_file)
    else:
        my_pillar = get_external_pillar_dictionary(minion_id)

    return my_pillar