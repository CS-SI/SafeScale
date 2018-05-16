#### Installs and configure common tools for any kind of nodes ####

export LANG=C

(
    # Disables installation of docker-python from yum
    yum remove -y python-docker-py &>/dev/null
    yum install -y yum-versionlock wget
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

    # Enables docker yum repo
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

    # Creates docker systemd directory
    mkdir -p /etc/systemd/system/docker.service.d && chmod 0755 /etc/systemd/system/docker.service.d

    # Configure docker to use overlay driver
    echo >/etc/systemd/system/docker.service.d/override.conf <<- EOF
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --storage-driver=overlay --log-driver=none
EOF

    # Installs docker
    yum upgrade --assumeyes --tolerant
    yum update --assumeyes
    yum install -y docker-ce-17.06.2.ce

    # Enable docker at boot
    systemctl enable docker.service
    systemctl start docker

    # Enables admin user to use docker
    usermod -aG docker gpac
) >/dev/null
####
