# Reporting about systems by groups from SUSE Manager (SMLM)

This reporting script generates reports in HTML format and send them via email.

The required login password can be encrypted using encrypt.py. The encryption and decryption salt key must be stored in a yaml file in the same directory of [suma_report.py](suma_report.py).

## Config required:

a config file with all required parameters must be provided. See sample config [suma_config.yaml](suma_config.yaml)

## Run reporting by groups
```
python3.6 suma_report.py --config=./suma_config.yaml --groups=group1,group2,group3
```

If no groups key is provided then the script will report all systems.



## Report by Technology 
The script [suma_report_by_technology.py](suma_report_by_technology.py) generates reports by technology and sends them via email.

In the [suma_config.yaml](suma_config.yaml) file, the technology groups must be defined in the `groups_definition: "gruppen.yaml"`. [gruppen.yaml](gruppen.yaml) is a sample file that defines the technology groups and their email recipients.

The groups and email recipients of each technology will be reported and receive the report.

```
python3.6 suma_report_by_technology.py --config=./suma_config.yaml
```