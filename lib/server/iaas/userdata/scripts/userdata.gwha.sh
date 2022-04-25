#!/bin/bash -x
#
# Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

#{{.Revision}}
# Script customized for {{.ProviderName}} driver

{{.Header}}

last_error=

function print_error() {
  read -r line file <<< "$(caller)"
  echo "An error occurred in line $line of file $file:" "{$(sed "${line}q;d" "$file")}" >&2
  {{.ExitOnError}}
}
trap print_error ERR

function fail() {
  MYIP="$(ip -br a | grep UP | awk '{print $3}') | head -n 1"
  if [ $# -eq 1 ]; then
    echo "PROVISIONING_ERROR: $1"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$1" > /opt/safescale/var/state/user_data.gwha.done
    (
      sync
      echo 3 > /proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  elif [ $# -eq 2 -a $1 -ne 0 ]; then
    echo "PROVISIONING_ERROR: $1, $2"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$2" > /opt/safescale/var/state/user_data.gwha.done
    (
      sync
      echo 3 > /proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  fi
}
export -f fail

# Redirects outputs to /opt/safescale/log/user_data.phase2.log
LOGFILE=/opt/safescale/var/log/user_data.phase2.log

### All output to one file and all output to the screen
{{- if .Debug }}
if [[ -e /home/{{.Username}}/tss ]]; then
  exec > >(/home/{{.Username}}/tss | tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
else
  exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
fi
{{- else }}
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
{{- end }}

set -x

date

# Tricks BashLibrary's waitUserData to believe the current phase 'gwha' is already done (otherwise will deadlock)
uptime > /opt/safescale/var/state/user_data.gwha.done

# Includes the BashLibrary
{{ .reserved_BashLibrary }}
rm -f /opt/safescale/var/state/user_data.gwha.done

function install_keepalived() {
  case $LINUX_KIND in
  ubuntu | debian)
    sfApt install -y keepalived || return 1
    ;;

  redhat | centos)
    sfYum install -q -y keepalived || return 1
    ;;
  *)
    echo "Unsupported Linux distribution '$LINUX_KIND'!"
    return 1
    ;;
  esac

  NETMASK=$(echo {{ .CIDR }} | cut -d/ -f2)
  read IF_PR ignore <<< $(cat ${SF_VARDIR}/state/private_nics)
  read IF_PU ignore <<< $(cat ${SF_VARDIR}/state/public_nics)

  cat > /etc/keepalived/keepalived.conf <<- EOF
		vrrp_instance vrrp_group_gws_internal {
		    state BACKUP
		    interface ${IF_PR}
		    virtual_router_id 1
		    priority {{ if eq .IsPrimaryGateway true }}151{{ else }}100{{ end }}
		    nopreempt
		    advert_int 2
		    authentication {
		        auth_type PASS
		        auth_pass "{{ .GatewayHAKeepalivedPassword }}"
		    }
		{{ if eq .IsPrimaryGateway true }}
		    # Unicast specific option, this is the IP of the interface keepalived listens on
		    unicast_src_ip {{ .PrimaryGatewayPrivateIP }}
		    # Unicast specific option, this is the IP of the peer instance
		    unicast_peer {
		        {{ .SecondaryGatewayPrivateIP }}
		    }
		{{ else }}
		    unicast_src_ip {{ .SecondaryGatewayPrivateIP }}
		    unicast_peer {
		        {{ .PrimaryGatewayPrivateIP }}
		    }
		{{ end }}
		    virtual_ipaddress {
		        {{ .DefaultRouteIP }}/${NETMASK}
		    }
		}
		
		# vrrp_instance vrrp_group_gws_external {
		#     state BACKUP
		#     interface ${IF_PU}
		#     virtual_router_id 2
		#     priority {{ if eq .IsPrimaryGateway true }}151{{ else }}100{{ end }}
		#     nopreempt
		#     advert_int 2
		#     authentication {
		#         auth_type PASS
		#         auth_pass password
		#     }
		#     virtual_ipaddress {
		#         {{ .EndpointIP }}/${NETMASK}
		#     }
		# }
	EOF

  if [ "$(sfGetFact "use_systemd")" = "1" ]; then
    # Use systemd to ensure keepalived is restarted if network is restarted
    # (otherwise, keepalived is in undetermined state)
    mkdir -p /etc/systemd/system/keepalived.service.d
    if [ "$(sfGetFact "redhat_like")" = "1" ]; then
      cat > /etc/systemd/system/keepalived.service.d/override.conf << EOF
[Unit]
Requires=network.service
PartOf=network.service
EOF
    else
      cat > /etc/systemd/system/keepalived.service.d/override.conf << EOF
[Unit]
Requires=systemd-networkd.service
PartOf=systemd-networkd.service
EOF
    fi
    systemctl daemon-reload
  fi

  sfService enable keepalived && sfService restart keepalived || return 1

  return 0
}

# ---- Main
{{- if .IsGateway }}
{{- if .SecondaryGatewayPrivateIP }}
install_keepalived
[ $? -ne 0 ] && fail $?
{{ end }}
{{ end }}
# ---- EndMain

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.gwha.done

(
  sync
  echo 3 > /proc/sys/vm/drop_caches
  sleep 2
) || true

set +x
exit 0
