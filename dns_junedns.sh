#!/usr/bin/bash

// JuNeDNS-acme - (c) 2024 Eduardo Ruiz Moreno
#https://github.com/acmesh-official/acme.sh/wiki/DNS-API-Dev-Guide

# Add to account.conf
#JUNEDNS_DBName=''
#JUNEDNS_DBUser=''
#JUNEDNS_DBPass=''

function _get_root() {
	IFS="." PS=($1)
	CNT=${#PS[@]}
	echo ${PS[$CNT-2]}.${PS[$CNT-1]}
}

dns_junedns_add() {
	fulldomain=$1
	txtvalue=$2

	if [ -z "$JUNEDNS_DBUser" ] || [ -z "$JUNEDNS_DBPass" ] || [ -z "$JUNEDNS_DBName" ]; then
    		_err "You don't specify JuNeDNS database parameters"
		return 1
	fi

	d=$(_get_root $fulldomain)
	did=$(mysql -u$JUNEDNS_DBUser -p$JUNEDNS_DBPass $JUNEDNS_DBName -BNe "SELECT id FROM domains WHERE name='$d'")
	if [ -z $did ]; then
		_err "JuNeDNS: Domain not found"
		return 1
	else
		id=$(mysql -u$JUNEDNS_DBUser -p$JUNEDNS_DBPass $JUNEDNS_DBName -BNe "SELECT id FROM records WHERE domain_id=$did AND name='$fulldomain'")
		if [ -z $id ]; then
			_debug "JuNeDNS: Creating DNS $d"
			mysql -u$JUNEDNS_DBUser -p$JUNEDNS_DBPass $JUNEDNS_DBName -e "INSERT INTO records SET domain_id=$did, name='$fulldomain', type='TXT', content='\"$txtvalue\"', ttl=60"
		else
			_debug "JuNeDNS: Updating DNS $d"
			mysql -u$JUNEDNS_DBUser -p$JUNEDNS_DBPass $JUNEDNS_DBName -e "UPDATE records SET content='\"$txtvalue\"' WHERE id=$id"
		fi
		return 0
	fi
}

dns_junedns_rm() {
	fulldomain=$1
	txtvalue=$2
	return 0
}
