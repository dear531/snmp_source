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
	snmp_sess_init(&session);
	session.peername			= "test.net-snmp.org";
#ifdef DEMO_USE_SNMP_VERSION_3
	session.version				= SNMP_VERSION_3;
	session.securityName		= strdup("MD5User");
	session.securityNameLen 	= strlen(session.securityName);
	session.securityLevel		= SNMP_SEC_LEVEL_AUTHNOPRIV;
	session.securityAuthProto	= usmHMACMD5AuthProtocol;
	session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol) / sizeof(oid);
	session.securityAuthKeyLen	= USM_AUTH_KU_LEN;
	if (generate_Ku(session.securityAuthProto,
					session.securityAuthProtoLen,
					(u_char *)our_v3_passphrase,
					strlen(our_v3_passphrase),
					session.securityAuthKey,
					&session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
		snmp_perror(argv[0]);
		snmp_log(LOG_ERR,
			"Error generating KU from authentication pass phrase.\n");
		exit(EXIT_FAILURE);
#else /* we'll use the insecure (but simplier) SNMPv1 */
		session.version			= SNMP_VERSION_1;
		session.community		= "demopubic";
		session.community_len	= strlen(session.community);
#endif /* end of version 3 and 1 */
		ss				= snmp_open(&session);
		if (!ss) {
			snmp_perror(argv[0]);
			snmp_log(LOG_ERR,
				"open the session failure\n");
			exit(EXIT_FAILURE);
		}
		pdu				= snmp_pdu_create(SNMP_MSG_GET);
	}
	read_objid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len);
#if OTHER_METHODS
	get_node("sysDescr.0", anOID, &anOID_len);
	read_objid("system.sysDescr.0", anOID, &anOID_len);
#endif
	snmp_add_null_var(pdu, anOID, anOID_len);
	status				= snmp_synch_response(ss, pdu, &response);
	if (status == STAT_SUCCESS && response->errstat ==
			SNMP_ERR_NOERROR) {
		for (vars = response->variables; vars; vars = vars->next_variable)
			print_variable(vars->name, vars->name_length, vars);
		for (vars = response->variables; vars; vars = vars->next_variable) {
			int count = 1;
			if (vars->type == ASN_OCTET_STR) {
				char *sp = malloc(1 + vars->val_len);
				memcpy(sp, vars->val.string, vars->val_len);
				sp[vars->val_len] = '\0';
				printf("value #%d is a string: %s\n", count++, sp);
				free(sp);
			} else {
				printf("value #%d is not a string! ack!\n", count++);
			}
		}
	} else {
		if (status == STAT_SUCCESS)
			fprintf(stderr, "Error in packet\n Reason: %s\n",
					snmp_errstring(response->errstat));
		else
			snmp_sess_perror("snmpget", ss);
	}
	if (!response)
		free(response);
	snmp_close(ss);

	return 0;
}
/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
