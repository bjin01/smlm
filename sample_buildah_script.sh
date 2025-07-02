#!/bin/bash
IMAGE_NAME="registry.suse.com/suse/manager/5.0/x86_64/server"
IMAGE_TAG="5.0.4.1"
THIS_FQDN=$(hostname -f)
SYSTEMD_OVERRIDE="/etc/systemd/system/uyuni-server.service.d/override.conf"
REPO1="https://download.opensuse.org/repositories/security/15.6/security.repo"
SUMA_VOLUME="/var/lib/containers/storage/volumes"
container=$(buildah from ${IMAGE_NAME}:${IMAGE_TAG})

printf "\nInstalling additional software mailx netcat git-core duo_unix\n"
buildah run $container zypper ar ${REPO1}
buildah run $container zypper --gpg-auto-import-keys refresh 2>1 >/dev/null
buildah run $container zypper -q install -y mailx netcat git-core duo_unix 2>1 >/dev/null

printf "Copy /etc/duo/pam_duo.conf into container\n"
buildah copy $container pam_duo.conf /etc/duo/pam_duo.conf
buildah run $container chmod 600 /etc/duo/pam_duo.conf

printf "rsync ldap.crt and sssd.conf into persistent volume\n"
rsync -qav ldap.crt ${SUMA_VOLUME}/etc-tls/_data/certs/ldap.crt
rsync -qav sssd.conf ${SUMA_VOLUME}/etc-sssd/_data/sssd.conf

printf "run pam-config -a --sss\n"
buildah run $container pam-config -a --sss

printf "copy /etc/pam.d/susemanager-auth into container.\n"
buildah copy $container susemanager-auth /etc/pam.d/susemanager-auth

printf "Show /etc/pki/tls/certs \n"
buildah run \
--volume ${SUMA_VOLUME}/etc-tls/_data/:/etc/pki/tls:rw \
$container \
ls -la /etc/pki/tls/certs

printf "Commit container into image.\n"
buildah commit -q $container ${IMAGE_NAME}:${IMAGE_TAG}
buildah rm $container

printf "Adapt ${SYSTEMD_OVERRIDE}\n"
cat <<EOF > ${SYSTEMD_OVERRIDE}
[Service]
Environment=UYUNI_IMAGE=${IMAGE_NAME}:${IMAGE_TAG}
Environment="PODMAN_EXTRA_ARGS=--add-host=${THIS_FQDN}:127.0.0.1"
EOF
systemctl daemon-reload

podman images ${IMAGE_NAME}:${IMAGE_TAG}
printf "\nMit diesem Befehl kann der SUSE Manager mit dem neuen Image restarted werden.\n"
printf "\n\tmgradm restart\n"
