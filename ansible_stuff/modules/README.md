This ansible module "suma_module" is used to manage SUSE Manager (SUMA) systems. It allows you to perform various operations such as schedule updates, schedule package list refresh and loop check for job status.

The module requires a config file to be present in the same directory where decrypt_password.py and the respective playbook yaml file are placed. [suma_config.yaml](suma_config.yaml)

The required login password can be encrypted using encrypt.py. The encryption and decryption salt key must be stored in a file in the same directory of [decrypt_password.py](decrypt_password.py) and the respective playbook yaml file.

To use the module take a look at the example playbook files in this directory e.g. [suma_plays](test_suma_play.yml). The playbook files are named with the prefix "suma_" and contain examples of how to use the module.

