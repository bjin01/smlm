FROM registry.suse.com/bci/python:3.11

WORKDIR /app
RUN zypper -n ar --no-gpgcheck https://download.opensuse.org/repositories/systemsmanagement:/Uyuni:/Stable/charts/systemsmanagement:Uyuni:Stable.repo
RUN zypper -n install -y postgresql-18 postgresql-contrib \
spacecmd vim smdba spacewalk-remote-utils iputils \
iproute2 netcat-openbsd \
python311-tornado python311-looseversion python311-msgpack python311-distro python311-jinja2

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY smdba/basegate.py /usr/lib/python3.6/site-packages/smdba/
COPY smdba/postgresqlgate.py /usr/lib/python3.6/site-packages/smdba/

RUN sed -i 's/^postgres:!:.*:/postgres:x:999:/g' /etc/group
RUN sed -i 's/^postgres:x:.*/postgres:x:999:999::\/var\/lib\/pgsql:\/bin\/bash/g' /etc/passwd
RUN chown -R postgres:postgres /var/lig/pgsql
RUN echo "salt:x:10554:" >> /etc/group
RUN echo "salt:!:20509::::::" >> /etc/shadow
RUN echo  "salt:x:10554:10554::/var/lib/salt:/usr/sbin/nologin" >> /etc/passwd

RUN mkdir /var/lib/salt
RUN chown -R salt:salt /var/lib/salt

RUN mkdir -p /tmp/mybackup
RUN chown -R postgres:postgres /tmp/mybackup
RUN chmod -R 700 /tmp/mybackup

COPY . .
