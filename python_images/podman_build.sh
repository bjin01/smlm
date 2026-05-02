#!/bin/bash

IMAEG_NAME=bopy
if [ -z "$1" ]
then
    DOCKERFILE=$PWD/Dockerfile
else
    DOCKERFILE=$1
fi

salt_shareduser=mysalt
salt_sharedsecret=suselinux
salt_master_tornado_port=8088

rhn_config=/var/lib/containers/storage/volumes/etc-rhn/_data/rhn.conf
DB_USER=$(cat /var/lib/containers/storage/volumes/etc-rhn/_data/rhn.conf | grep -E "^db_user = " | tr -d [:blank:] | awk -F= '{ print $2 }')
DB_PWD=$(cat /var/lib/containers/storage/volumes/etc-rhn/_data/rhn.conf | grep -E "^db_password = " | tr -d [:blank:] | awk -F= '{
print $2 }')

#echo $DB_USER
#echo $DB_PWD

sed -i "s/^ENV.*DB_USER.*/ENV DB_USER=${DB_USER}/g" Dockerfile
sed -i "s/^ENV.*DB_PWD.*/ENV DB_PWD=${DB_PWD}/g" Dockerfile
sed -i "s/^ENV.*SALT_API_USER.*/ENV SALT_API_USER=${salt_shareduser}/g" Dockerfile
sed -i "s/^ENV.*SALT_API_SECRET.*/ENV SALT_API_SECRET=${salt_sharedsecret}/g" Dockerfile
sed -i "s/^ENV.*SALT_API_PORT.*/ENV SALT_API_PORT=${salt_master_tornado_port}/g" Dockerfile

#echo $DOCKERFILE
podman build --layers --force-rm --squash-all --tag $IMAEG_NAME -f $DOCKERFILE

