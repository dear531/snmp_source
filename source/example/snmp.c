#include <stdio.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/* change the word "define" to "undef" to try the (insecure) SNMPv1 version */
#define DEMO_USE_SNMP_VERSION_3

#ifdef DEMO_USE_SNMP_VERSION_3
const char *our_v3_passphrase = "The Net-SNMP Demo password";
#endif

#include <net-snmp/session_api.h>

int
main(int argc, char *argv[])
{
	struct snmp_session	session, *ss;
	struct snmp_pdu		*pdu;
	struct snmp_pdu		*response;
	oid					anOID[MAX_OID_LEN];
	size_t				anOID_len	= MAX_OID_LEN;
	struct variable_list *vars;
	int					status;
	
	init_snmp("snmpapp");
	snmp_sses_init(&session);
	session.peername			= "test.net-snmp.org";
	session.version				= DEMO_USE_SNMP_VERSION_3;
	session.securityName		= strdup("MD5User");
	session.securityNameLen 	= strlen(session.securityName);
	session.securityLevel		= SNMP_SEC_LEVEL_AUTHNOPRIV;
	session.securityAuthProto	= usmHMACMD5AuthProtocol;
	session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol) / sizeof(oid);
	session.securityAuthKeyLen	= USM_AUTH_KU_LEN;

	return 0;
}
