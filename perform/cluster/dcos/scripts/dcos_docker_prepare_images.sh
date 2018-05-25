# Prepares docker images needed to the deployment
#
# This script has to be executed on the bootstrap/upgrade server

mkdir /usr/local/dcos/genconf/serve/docker

{{ .PrepareImageGuacamole }}
{{ .PrepareImageProxy }}

############################################################
# docker-compose file to starts guacamole+proxy containers #
############################################################

cat >/usr/local/dcos/genconf/serve/docker/docker-compose.yml <<-EOF
version: '3'

services:
    guacamole:
        container_name: guacamole
        hostname: guacamole
        image: guacamole:latest
        networks:
            default:

    proxy:
        container_name: proxy
        hostname: proxy
        image: proxy:latest
        ports:
            - 443:443
        networks:
            default:

networks:
    default:
        driver: bridge

EOF

################
# Some cleanup #
################

docker image prune -f
