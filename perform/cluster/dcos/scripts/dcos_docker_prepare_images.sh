# Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Prepares docker images needed for the deployment
#
# This script has to be executed on the bootstrap/upgrade server

mkdir -p /usr/local/dcos/genconf/serve/docker

{{ .PrepareImageGuacamole }}
{{ .PrepareImageProxy }}

############################################################
# docker-compose file to starts guacamole+proxy containers #
############################################################

cat >/usr/local/dcos/genconf/serve/docker/dcos-master.yml <<-'EOF'
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

#docker image prune -f

###