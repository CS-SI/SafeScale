#### Installs and configure common tools for any kind of nodes ####

export LANG=C

(

    # Disable SELinux
    setenforce 0
    sed -i 's/^SELINUX=.*$/SELINUX=disabled/g' /etc/sysconfig/selinux

    # Disables firewall
    systemctl stop firewalld 2>/dev/null
    systemctl disable firewalld 2>/dev/null

    # Upgrade to last CentOS revision
    rm -rf /usr/lib/python2.7/site-packages/backports.ssl_match_hostname-3.5.0.1-py2.7.egg-info
    yum install -y python-backports-ssl_match_hostname
    yum upgrade --assumeyes --tolerant
    yum update --assumeyes

    # Create group nogroup
    groupadd nogroup

    # Disables installation of docker-python from yum
    yum remove -y python-docker-py &>/dev/null
    yum install -y yum-versionlock tar xz curl wget unzip ipset pigz
    yum versionlock exclude python-docker-py

    # Installs PIP
    yum install -y epel-release
    yum install -y python-pip

    # Installs docker-python with pip
    pip install -q docker-py==1.10.6 docker-compose

    # Enable overlay module
    echo overlay >/etc/modules-load.d/10-overlay.conf

    # Loads overlay module
    modprobe overlay

    # Creates docker systemd directory
    mkdir -p /etc/systemd/system/docker.service.d && chmod 0755 /etc/systemd/system/docker.service.d

    # Configure docker to use overlay driver
    echo >/etc/systemd/system/docker.service.d/override.conf <<- EOF
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --storage-driver=overlay --log-driver=none
EOF

    # Installs docker
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum install -y docker-ce-17.06.2.ce

    # Enable docker at boot
    systemctl enable docker.service
    systemctl start docker

    # Enables admin user to use docker
    usermod -aG docker gpac

    # Creates user cladm
    useradd -s /bin/bash -m -d /home/cladm cladm
    usermod -aG docker cladm
    mkdir -p /home/cladm/.ssh && chmod 0700 /home/cladm/.ssh
    echo >/home/cladm/.ssh/authorized_keys <<- EOF
{{ .SSHPublicKey }}
EOF
    chmod 0600 /home/cladm/.ssh/authorized_keys && chown -R cladm:cladm /home/cladm

) >/dev/null
####
