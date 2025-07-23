#!/bin/bash
# Date: 23/07/2025
# Author: Bo Jin
# This script is used to adapt SMLM default podman image into a custom image 

# Modified: 23/07/2025 
# Modified by: Bo Jin
# Modified: anonymized the script data 

# Requirements: 
#   - buildah, podman must be installed
#   - SMLM Images are present and SMLM initial setup is already finished.
#   - All neccessary config files and this bash script are located in one directory on the host

# Usage: # bash Build_Container.sh

# Major customizations done via this script:
#   - install additional Software
#   - add 3rd party CA certs
#   - add LDAP and sssd config files
#   - add custom coded binary (jobchecker)
#   - adapt postfix configurations
#   - rsync salt configs and salt states into persistent volumes
#   - set passwords and secrets in salt-master config files
#   - modify and change uyuni-server.service unit file on host for additional volume mount and port mappings
#   - commit into new image


IGNORE_FILE=".rsyncignore"
TODAY=$(date +%d%m%Y)
SMLM_IMAEG_NAME="my_SMLM_5041:${TODAY}"
printf "Creating new podman Image: ${SMLM_IMAEG_NAME}\n"
container=$(buildah from registry.suse.com/suse/manager/5.0/x86_64/server:5.0.4.1) 
mountpoint=$(buildah mount $container)
SMLM_VOLUME="/var/lib/containers/storage/volumes"
GIT_REPO_PATH="/appl/salt/xxx/bitbucket/smlm"
RPMs="man man-pages bash-completion hostname jq yq vim-data nmon git-core mailx netcat python3-pip python3-boltons python3-sortedcollections python3-ldap3"
#THIS_FQDN=$(hostname -f)

## below 4 params needed for jobchecker. 
## python3.6 encrypt OUR_PWD
THIS_FQDN=$(hostname -f)
SMLM_HOST="mysmlm.example.com"
SMLMKey=yDYDtLvKWov
ENC_PWD=gAAAAABj9JJ3Xu1v7qYt

#cp /etc/zypp/credentials.d/SCCcredentials $mountpoint/etc/zypp/credentials.d/SCCcredentials

## copy sssd.conf to persistent volume. 
printf "Copy sssd.conf into Container.\n"
cp /root/SMLM5/sssd/sssd.conf /var/lib/containers/storage/volumes/etc-sssd/_data/sssd.conf

printf "rsync ${GIT_REPO_PATH}/etc/salt/master.d/ into Container.\n"
rsync -qav --exclude-from=${IGNORE_FILE} ${GIT_REPO_PATH}/etc/salt/master.d/ ${SMLM_VOLUME}/etc-salt/_data/master.d/

printf "Verify if salt-master autosign_grains directory and subdir os_family exist.\n"
if [ ! -d ${SMLM_VOLUME}/etc-salt/_data/autosign_grains ]; then
    printf "\tMake directory: /etc/salt/autosign_grains/os_family in Container\n"
    mkdir -p ${SMLM_VOLUME}/etc-salt/_data/autosign_grains
    touch ${SMLM_VOLUME}/etc-salt/_data/autosign_grains/os_family
    cat <<-EOF > ${SMLM_VOLUME}/etc-salt/_data/autosign_grains/os_family
Suse
RedHat
EOF
else
    cat ${SMLM_VOLUME}/etc-salt/_data/autosign_grains/os_family
fi

cp /root/SMLM5/certs/* $mountpoint/etc/pki/trust/anchors/

buildah config \
  --env ADDITIONAL_MODULES=PackageHub,sle-module-web-scripting \
  --env http_proxy=http://myproxy.example.com:8080 \
  --env https_proxy=http://myproxy.example.com:8080 \
  --env no_proxy="localhost,127.0.0.1,mydomain.example.com" \
  $container
  
buildah run $container update-ca-certificates 

printf "rpm.install.excludedocs = yes in /etc/zypp/zypp.conf. We love to have manpages.\n"
buildah run $container sed -i 's/^rpm.install.excludedocs.*$/rpm.install.excludedocs = no/g' /etc/zypp/zypp.conf

printf "Make /appl directory in Container\n"
buildah run $container mkdir /appl

printf "Refresh zypper repos, It takes a bit time.\n"
buildah run $container zypper --gpg-auto-import-keys refresh 2>1 > /dev/null

printf "Installing Software packages.\n"
printf "\t${RPMs}\n"
buildah run $container zypper -q install -y ${RPMs} 2>1 > /dev/null
printf "pip3 install deepmerge\n"
buildah run $container pip3 install -q deepmerge

printf "mandb update.\n"
buildah run $container mandb 2>1 > /dev/null 

printf "Copy /etc/openldap/ldap.conf into container.\n"
buildah copy -q $container /root/SMLM5/ldap/ldap.conf /etc/openldap/ldap.conf

printf "Copy /etc/pki/trust/anchors/* /admin/certs/ into container.\n"
buildah run $container mkdir -p /admin/certs
buildah copy -q $container /etc/pki/trust/anchors/* /admin/certs/

printf "Copy /root/.bashrc into container.\n"
cp .bashrc ${SMLM_VOLUME}/root/_data/.bashrc

printf "Copy SMLM-jobchecker binary into container. \n"
if [ ! -d /appl/SMLM/jobchecker ]; then
    mkdir -p /appl/SMLM/jobchecker
fi
if [ ! -d ${SMLM_VOLUME}/var-log/_data/patching ]; then
    printf "\tmake directory: {SMLM_VOLUME}/var-log/_data/patching\n"
    mkdir -p ${SMLM_VOLUME}/var-log/_data/patching
    touch ${SMLM_VOLUME}/var-log/_data/patching/patching.log
fi
printf "Set /var/log/patching/patching.log permissions for jobchecker.\n"
buildah run \
--volume ${SMLM_VOLUME}/var-log/_data:/var/log:rw \
$container \
chown salt:salt /var/log/patching/patching.log

#printf "Erstelle /data/config/db Verzeichnis im Container.\n"
#buildah run $container mkdir -p /data/config/db

printf "Set /srv/pillar/exceptions /srv/pillar/sudoers permissions\n"
buildah run \
--volume ${SMLM_VOLUME}/srv-pillar/_data:/srv/pillar:rw \
$container \
chown -R salt:salt /srv/pillar/exceptions

buildah run \
--volume ${SMLM_VOLUME}/srv-pillar/_data:/srv/pillar:rw \
$container \
chown -R salt:salt /srv/pillar/sudoers

printf "rsync jobcheck/appl/SMLM/jobchecker/ /appl/SMLM/jobchecker\n"
rsync -qav --exclude-from=${IGNORE_FILE} jobcheck/appl/SMLM/jobchecker/ /appl/SMLM/jobchecker
rsync -qav --exclude-from=${IGNORE_FILE} jobcheck/jobmonitor /appl/SMLM/jobchecker/jobmonitor
buildah run \
--volume /appl/SMLM/jobchecker:/appl/SMLM/jobchecker:rw \
$container \
ls /appl/SMLM/jobchecker/jobmonitor && chmod 777 /appl/SMLM/jobchecker/jobmonitor


## Copy SMLM-jobchecker.service
buildah copy -q $container jobcheck/SMLM-jobchecker.service /etc/systemd/system/SMLM-jobchecker.service

buildah run \
--volume ${SMLM_VOLUME}/etc-systemd-multi/_data:/etc/systemd/system/multi-user.target.wants:rw \
$container \
systemctl enable SMLM-jobchecker.service   

#cp jobcheck/SMLM-jobchecker.service ${SMLM_VOLUME}/etc-systemd-multi/_data/SMLM-jobchecker.service
printf "\nSet SMLMkey und encrypted password by Script /root/scripts/change_secrets.sh within Container.\n"
if [ ! -d ${SMLM_VOLUME}/root/_data/scripts ]; then
    mkdir ${SMLM_VOLUME}/root/_data/scripts  
fi

printf "Run /root/_data/scripts/change_secrets.sh within Container to set SMLMkey and encrypted password\n"
cp encrypt.py ${SMLM_VOLUME}/root/_data/scripts/encrypt.py
cp change_secrets.sh ${SMLM_VOLUME}/root/_data/scripts/change_secrets.sh
buildah run \
--volume ${SMLM_VOLUME}/etc-salt/_data/master.d:/etc/salt/master.d:rw \
--volume /appl/SMLM/scripts:/appl/SMLM/scripts:rw \
--volume ${SMLM_VOLUME}/root/_data:/root:rw \
--volume ${SMLM_VOLUME}/srv-pillar/_data:/srv/pillar:rw \
$container \
bash /root/scripts/change_secrets.sh "${SMLMKey}" "${ENC_PWD}" "${SMLM_HOST}"

printf "\Set chown -R root:salt /etc/salt/master.d\n"
buildah run \
--volume ${SMLM_VOLUME}/etc-salt/_data/master.d:/etc/salt/master.d:rw \
$container \
chown -R root:salt /etc/salt/master.d

printf "Set chmod 640 /etc/salt/master.d/*\n"
buildah run --volume ${SMLM_VOLUME}/etc-salt/_data:/etc/salt:rw $container find /etc/salt/master.d -type f -exec chmod 640 {} +

printf "\nAdapt postfix files in container: /etc/postfix/generic.\n"
buildah run \
--volume ${SMLM_VOLUME}/etc-postfix/_data:/etc/postfix:rw \
$container \
echo "root@${THIS_FQDN} linux@mydoamin.example.com" > /etc/postfix/generic

printf "\nAdapt postfix files in container: /etc/postfix/sender_canonical.\n"
echo "SMLM@uyuni-server.mgr.internal SMLM5@${THIS_FQDN}" > ${SMLM_VOLUME}/etc-postfix/_data/sender_canonical

printf "\nAdapt postfix files in container: postmap /etc/postfix/sender_canonical.\n"
buildah run \
--volume ${SMLM_VOLUME}/etc-postfix/_data:/etc/postfix:rw \
$container \
postmap /etc/postfix/sender_canonical

printf "\nModify ${SMLM_VOLUME}/etc-sysconfig/_data/postfix\n"
cp sysconfig_postfix ${SMLM_VOLUME}/etc-sysconfig/_data/postfix

printf "Do c_rehash /admin/certs for special LDAP integration.\n"
buildah run $container c_rehash /admin/certs/ 

printf "chown salt-master Konfig my_ldap.conf im Container.\n"
buildah run \
--volume ${SMLM_VOLUME}/etc-salt/_data/master.d:/etc/salt/master.d:rw \
$container \
chown "salt:salt" /etc/salt/master.d/my_ldap.conf

printf "Copy ldap.conf und pam.d files into container.\n"
buildah copy -q $container ldap/ldap.conf /etc/openldap/ldap.conf
buildah copy -q $container pam/* /etc/pam.d/

printf "Import 3rd party repo pub keys *.asc files into container gpg keyring.\n"
if [ ! -d ${SMLM_VOLUME}/root/_data/gpg_keys ]; then
    printf "\tMake directory: ${SMLM_VOLUME}/root/_data/gpg_keys\n"
    mkdir -p ${SMLM_VOLUME}/root/_data/gpg_keys
fi

echo "" > ${SMLM_VOLUME}/root/_data/gpg_keys/all-in-one-pub-keys
for i in $(ls /root/SMLM5/repo_keys/*.asc); do cat $i >> ${SMLM_VOLUME}/root/_data/gpg_keys/all-in-one-pub-keys; done

buildah run \
--volume ${SMLM_VOLUME}/root/_data:/root:rw \
$container \
gpg -q --batch --no-options --no-default-keyring --no-permission-warning \
--keyring /var/lib/spacewalk/gpgdir/pubring.gpg --import /root/gpg_keys/all-in-one-pub-keys

printf "\nCommit into new image ${SMLM_IMAEG_NAME}\n"
buildah commit -q $container "${SMLM_IMAEG_NAME}"
printf "New podan image has been created successfully.\n"
buildah rm $container 2>1 > /dev/null 
buildah images | grep -E "SMLM.*${TODAY}"

printf "\nAdapt /etc/systemd/system/uyuni-server.service.d/override.conf\n"
cat <<EOF >/etc/systemd/system/uyuni-server.service.d/override.conf
[Service]
Environment=UYUNI_IMAGE="${SMLM_IMAEG_NAME}"
Environment="PODMAN_EXTRA_ARGS=--add-host=${THIS_FQDN}:127.0.0.1"
EOF

if ! grep -qE "\-p 45045:45045" /etc/systemd/system/uyuni-server.service; then
    printf "\nAdd port mapping for jobchecker -p 45045:45045 in /etc/systemd/system/uyuni-server.service\n"
    sed -i '/^\s-p 69:69\/udp/a\ \ \ \ \ \ \ \ -p \45045\:\45045 \\' /etc/systemd/system/uyuni-server.service
else
    printf "\njobchecker Port mapping 45045 is already present in /etc/systemd/system/uyuni-server.service\n"
fi

if ! grep -qE "/appl:/appl" /etc/systemd/system/uyuni-server.service; then
    printf "\nAdd volume mount -v /appl:/appl in /etc/systemd/system/uyuni-server.service\n"
    sed -i '/^\s-v etc-sssd/a\ \ \ \ \ \ \ \ -v \/appl\:\/appl \\' /etc/systemd/system/uyuni-server.service
else
    printf "\nvolume mount /appl is already present in /etc/systemd/system/uyuni-server.service\n"
fi

if ! grep -qE "/data/config:/data/config" /etc/systemd/system/uyuni-server.service; then
    printf "\nAdd volume mount -v /data/config/db:/data/config/db in /etc/systemd/system/uyuni-server.service\n"
    sed -i '/^\s-v etc-sssd/a\ \ \ \ \ \ \ \ -v \/data\/config\:\/data\/config \\' /etc/systemd/system/uyuni-server.service
else
    printf "\nvolume mount /data/config is already present in /etc/systemd/system/uyuni-server.service\n"
fi

systemctl daemon-reload
printf "\nSMLM can be restarted. \n### mgradm restart ###\n"