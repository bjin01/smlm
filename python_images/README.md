# SMLM container client

This is a containerized client for the SMLM project. It includes all the necessary dependencies and configurations to interact with the SMLM server.
smdba, spacecmd and python3.11 libs are included in the container, so you can use them to manage your SMLM environment.

Refer to Dockerfile to see the included dependencies and configurations. Adapt the Dockerfile as needed to include any additional tools or libraries you may require for your specific use case.

For smdba the /var/lib/pgsql/data and /etc/rhn directories are mounted to allow the container to access the necessary data and configuration files for PostgreSQL and RHN. This setup ensures that smdba can function properly within the container environment.

3rd party python scripts can be placed in the current directory and will be accessible within the container at /app. This allows you to easily run your custom scripts that interact with the SMLM server or perform other tasks related to your SMLM environment.

## Prerequisites:
- Podman installed on your system.
- Access to the SMLM server and necessary credentials.
- Properly configured rhn.conf file for database connection details.
- salt-master configuration for shared user and secret.
- salt-master should have tornado configured to listen on the specified port (default: 8088) for communication with the container.
- uyuni-db and uyuni-server containers are running and properly configured to allow connections from the client container.

## Set values in podman_build.sh:
salt_shareduser=mysalt
salt_sharedsecret=suselinux
salt_master_tornado_port=8088

The other values for db_user, db_password, db_name, and db_host will be set according to your rhn.conf in /var/lib/containers/storage/volumes/etc-rhn/_data/rhn.conf. 

## Build podman image:
In the ./python_images directory run:

```
bash podman_build.sh
```

## Sample usage:
Run the container with the following command, which mounts the current directory and necessary volumes for configuration and data storage. Adjust the volume mounts as needed for your environment.

```
podman run -it --rm -v "$PWD":/app:Z -v etc-rhn:/etc/rhn \
-v etc-salt:/etc/salt -v var-pgsql:/var/lib/pgsql/data \
-v srv-pillar:/srv/pillar \
-w /app --network uyuni --name boclient localhost/bopy:latest bash
```

Run the container without an interactive shell to execute commands directly:

```
podman run --rm -v "$PWD":/app:Z -w /app localhost/bopy:latest spacecmd -- system_list
```

Or to run a Python script:

```
podman run --rm -v "$PWD":/app:Z -v etc-rhn:/etc/rhn \
-v etc-salt:/etc/salt -v var-pgsql:/var/lib/pgsql/data \
-v srv-pillar:/srv/pillar \
-w /app --network uyuni \
--name boclient localhost/bopy:latest python3.11 /app/find_groups.py
```

To build the container image, use the following command in the directory containing the Dockerfile:

```
bash podman_build.sh
# or
podman build -t bopy .
```

