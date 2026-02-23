#!/bin/vbash
# fw01-menu.sh  (VyOS menu script)
# Put in: /config/scripts/fw01-menu.sh
# Run:    sudo chmod +x /config/scripts/fw01-menu.sh && sudo /config/scripts/fw01-menu.sh

source /opt/vyatta/etc/functions/script-template

apply_full_config() {
  configure

  # ---------------- FIREWALL POLICIES ----------------
  set firewall ipv4 name DMZ-to-LAN default-action 'drop'
  set firewall ipv4 name DMZ-to-LAN default-log
  set firewall ipv4 name DMZ-to-LAN rule 1 action 'accept'
  set firewall ipv4 name DMZ-to-LAN rule 1 state 'established'
  set firewall ipv4 name DMZ-to-LAN rule 10 action 'accept'
  set firewall ipv4 name DMZ-to-LAN rule 10 description 'Wazuh Agent communication with wazuh server'
  set firewall ipv4 name DMZ-to-LAN rule 10 destination address '172.16.200.10'
  set firewall ipv4 name DMZ-to-LAN rule 10 destination port '1514-1515'
  set firewall ipv4 name DMZ-to-LAN rule 10 protocol 'tcp'
  set firewall ipv4 name DMZ-to-LAN rule 20 action 'accept'
  set firewall ipv4 name DMZ-to-LAN rule 20 description 'Connect to MGMT'
  set firewall ipv4 name DMZ-to-LAN rule 20 destination address '172.16.200.0/28'

  set firewall ipv4 name DMZ-to-WAN default-action 'drop'
  set firewall ipv4 name DMZ-to-WAN default-log
  set firewall ipv4 name DMZ-to-WAN rule 1 action 'accept'
  set firewall ipv4 name DMZ-to-WAN rule 1 state 'established'
  set firewall ipv4 name DMZ-to-WAN rule 10 action 'accept'
  set firewall ipv4 name DMZ-to-WAN rule 10 description 'Allow web01 to internet'
  set firewall ipv4 name DMZ-to-WAN rule 10 source address '0.0.0.0/0'

  set firewall ipv4 name LAN-to-DMZ default-action 'drop'
  set firewall ipv4 name LAN-to-DMZ default-log
  set firewall ipv4 name LAN-to-DMZ rule 1 action 'accept'
  set firewall ipv4 name LAN-to-DMZ rule 1 state 'established'
  set firewall ipv4 name LAN-to-DMZ rule 20 action 'accept'
  set firewall ipv4 name LAN-to-DMZ rule 20 description 'LAN to access web'
  set firewall ipv4 name LAN-to-DMZ rule 20 destination address '172.16.50.3'
  set firewall ipv4 name LAN-to-DMZ rule 20 destination port '80'
  set firewall ipv4 name LAN-to-DMZ rule 20 protocol 'tcp'
  set firewall ipv4 name LAN-to-DMZ rule 30 action 'accept'
  set firewall ipv4 name LAN-to-DMZ rule 30 description 'LAN to access ssh'
  set firewall ipv4 name LAN-to-DMZ rule 30 destination address '172.16.50.3'
  set firewall ipv4 name LAN-to-DMZ rule 30 destination port '22'
  set firewall ipv4 name LAN-to-DMZ rule 30 protocol 'tcp'
  set firewall ipv4 name LAN-to-DMZ rule 40 action 'accept'
  set firewall ipv4 name LAN-to-DMZ rule 40 description 'LAN—--ssh-->DMZ'
  set firewall ipv4 name LAN-to-DMZ rule 40 destination address '172.16.50.0/29'
  set firewall ipv4 name LAN-to-DMZ rule 40 destination port '22'
  set firewall ipv4 name LAN-to-DMZ rule 40 protocol 'tcp'

  set firewall ipv4 name LAN-to-WAN default-action 'drop'
  set firewall ipv4 name LAN-to-WAN default-log
  set firewall ipv4 name LAN-to-WAN rule 1 action 'accept'

  set firewall ipv4 name WAN-to-DMZ default-action 'drop'
  set firewall ipv4 name WAN-to-DMZ default-log
  set firewall ipv4 name WAN-to-DMZ rule 1 action 'accept'
  set firewall ipv4 name WAN-to-DMZ rule 1 state 'established'
  set firewall ipv4 name WAN-to-DMZ rule 10 action 'accept'
  set firewall ipv4 name WAN-to-DMZ rule 10 destination address '172.16.50.3'
  set firewall ipv4 name WAN-to-DMZ rule 10 destination port '80'
  set firewall ipv4 name WAN-to-DMZ rule 10 protocol 'tcp'
  set firewall ipv4 name WAN-to-DMZ rule 20 action 'accept'
  set firewall ipv4 name WAN-to-DMZ rule 20 destination address '172.16.50.4'
  set firewall ipv4 name WAN-to-DMZ rule 20 destination port '22'
  set firewall ipv4 name WAN-to-DMZ rule 20 protocol 'tcp'

  set firewall ipv4 name WAN-to-LAN default-action 'drop'
  set firewall ipv4 name WAN-to-LAN default-log
  set firewall ipv4 name WAN-to-LAN rule 1 action 'accept'
  set firewall ipv4 name WAN-to-LAN rule 1 state 'established'

  # ---------------- ZONES ----------------
  set firewall zone DMZ from LAN firewall name 'LAN-to-DMZ'
  set firewall zone DMZ from WAN firewall name 'WAN-to-DMZ'
  set firewall zone DMZ member interface 'eth1'

  set firewall zone LAN from DMZ firewall name 'DMZ-to-LAN'
  set firewall zone LAN from WAN firewall name 'WAN-to-LAN'
  set firewall zone LAN member interface 'eth2'

  set firewall zone WAN from DMZ firewall name 'DMZ-to-WAN'
  set firewall zone WAN from LAN firewall name 'LAN-to-WAN'
  set firewall zone WAN member interface 'eth0'

  # ---------------- INTERFACES ----------------
  set interfaces ethernet eth0 address '10.0.17.119/24'
  set interfaces ethernet eth0 description 'SEC350-WAN'
  set interfaces ethernet eth0 offload gro
  set interfaces ethernet eth0 offload gso
  set interfaces ethernet eth0 offload sg
  set interfaces ethernet eth0 offload tso

  set interfaces ethernet eth1 address '172.16.50.2/29'
  set interfaces ethernet eth1 description 'Hamed-DMZ'

  set interfaces ethernet eth2 address '172.16.150.2/24'
  set interfaces ethernet eth2 description 'Hamed-LAN'

  # ---------------- NAT ----------------
  set nat destination rule 10 description 'HTTP—---->DMZ'
  set nat destination rule 10 destination port '80'
  set nat destination rule 10 inbound-interface name 'eth0'
  set nat destination rule 10 protocol 'tcp'
  set nat destination rule 10 translation address '172.16.50.3'
  set nat destination rule 10 translation port '80'

  set nat destination rule 20 description 'RW01—---->Jumper'
  set nat destination rule 20 destination port '22'
  set nat destination rule 20 inbound-interface name 'eth0'
  set nat destination rule 20 protocol 'tcp'
  set nat destination rule 20 translation address '172.16.50.4'
  set nat destination rule 20 translation port '22'

  set nat source rule 10 description 'NAT FROM DMZ TO WAN'
  set nat source rule 10 outbound-interface name 'eth0'
  set nat source rule 10 source address '172.16.50.0/29'
  set nat source rule 10 translation address 'masquerade'

  set nat source rule 20 description 'NAT FROM LAN TO WAN'
  set nat source rule 20 outbound-interface name 'eth0'
  set nat source rule 20 source address '172.16.150.0/24'
  set nat source rule 20 translation address 'masquerade'

  set nat source rule 30 description 'NAT FROM MGMT TO WAN'
  set nat source rule 30 translation address 'masquerade'

  # ---------------- ROUTING / SERVICES ----------------
  set protocols rip interface eth2
  set protocols rip network '172.16.50.0/29'
  set protocols static route 0.0.0.0/0 next-hop 10.0.17.2

  set service dns forwarding allow-from '172.16.50.0/29'
  set service dns forwarding allow-from '172.16.150.0/24'
  set service dns forwarding listen-address '172.16.50.2'
  set service dns forwarding listen-address '172.16.150.2'
  set service dns forwarding system

  set service ssh

  # ---------------- SYSTEM ----------------
  set system host-name 'FW01-Hamed'
  set system name-server '10.0.17.2'
  set system option reboot-on-upgrade-failure '5'
  set system syslog local facility all level 'info'
  set system syslog local facility local7 level 'debug'
  set system syslog remote 172.16.50.5 facility authpriv

  # Commit + Save
  commit
  save
  exit
  echo "DONE: Full config applied, committed, and saved."
}

show_zone_firewall() {
  echo
  echo "---- Zone policy bindings ----"
  run show configuration commands | match "set firewall zone"
  echo
  echo "---- Firewall policy names ----"
  run show configuration commands | match "set firewall ipv4 name"
  echo
}

show_nat() {
  echo
  echo "---- NAT rules ----"
  run show configuration commands | match "set nat "
  echo
}

show_interfaces_routes() {
  echo
  echo "---- Interfaces ----"
  run show interfaces
  echo
  echo "---- Routes ----"
  run show ip route
  echo
}

rollback_last() {
  configure
  rollback 1
  commit
  save
  exit
  echo "DONE: Rolled back 1 commit, committed, and saved."
}

menu() {
  while true; do
    echo
    echo "=============================="
    echo " FW01-Hamed VyOS Menu"
    echo "=============================="
    echo "1) Apply FULL config (your commands)"
    echo "2) Show firewall zones + policies"
    echo "3) Show NAT rules"
    echo "4) Show interfaces + routes"
    echo "5) Rollback last commit (rollback 1)"
    echo "6) Exit"
    echo
    read -r -p "Select (1-6): " choice

    case "$choice" in
      1) apply_full_config ;;
      2) show_zone_firewall ;;
      3) show_nat ;;
      4) show_interfaces_routes ;;
      5) rollback_last ;;
      6) exit 0 ;;
      *) echo "Invalid choice." ;;
    esac
  done
}

menu
