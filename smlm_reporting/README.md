# Reporting about systems by groups

This reporting script is used to generate reports in HTML format from the SMLM API and send them via email.

The required login password can be encrypted using encrypt.py. The encryption and decryption salt key must be stored in a yaml file in the same directory of [suma_report.py](suma_report.py).

## Config required:

a config file with all required parameters must be provided. See sample config [suma_config.yaml](suma_config.yaml)

## Run reporting
```
python3.6 suma_report.py groups=group1,group2,group3
```

If no groups key is provided then the script will report all systems.

The sample html output [report.html](report.html)



