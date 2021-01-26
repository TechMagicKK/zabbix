/*
** Zabbix
** Copyright (C) 2001-2021 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

#include "common.h"
#include "../poller/checks_agent.h"
#include "../ipmi/ipmi.h"
#include "../poller/checks_ssh.h"
#include "../poller/checks_telnet.h"
#include "zbxexec.h"
#include "zbxserver.h"
#include "db.h"
#include "log.h"
#include "zbxtasks.h"
#include "scripts.h"
#include "zbxjson.h"
#include "zbxembed.h"
#include "../events.h"

extern int	CONFIG_TRAPPER_TIMEOUT;
extern int	CONFIG_IPMIPOLLER_FORKS;

static int	zbx_execute_script_on_agent(const DC_HOST *host, const char *command, char **result,
		char *error, size_t max_error_len)
{
	int		ret;
	AGENT_RESULT	agent_result;
	char		*param = NULL, *port = NULL;
	DC_ITEM		item;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	*error = '\0';
	memset(&item, 0, sizeof(item));
	memcpy(&item.host, host, sizeof(item.host));

	if (SUCCEED != (ret = DCconfig_get_interface_by_type(&item.interface, host->hostid, INTERFACE_TYPE_AGENT)))
	{
		zbx_snprintf(error, max_error_len, "Zabbix agent interface is not defined for host [%s]", host->host);
		goto fail;
	}

	port = zbx_strdup(port, item.interface.port_orig);
	substitute_simple_macros(NULL, NULL, NULL, NULL, &host->hostid, NULL, NULL, NULL, NULL, NULL,
			&port, MACRO_TYPE_COMMON, NULL, 0);

	if (SUCCEED != (ret = is_ushort(port, &item.interface.port)))
	{
		zbx_snprintf(error, max_error_len, "Invalid port number [%s]", item.interface.port_orig);
		goto fail;
	}

	param = zbx_strdup(param, command);
	if (SUCCEED != (ret = quote_key_param(&param, 0)))
	{
		zbx_snprintf(error, max_error_len, "Invalid param [%s]", param);
		goto fail;
	}

	item.key = zbx_dsprintf(item.key, "system.run[%s%s]", param, NULL == result ? ",nowait" : "");
	item.value_type = ITEM_VALUE_TYPE_TEXT;

	init_result(&agent_result);

	zbx_alarm_on(CONFIG_TIMEOUT);

	if (SUCCEED != (ret = get_value_agent(&item, &agent_result)))
	{
		if (ISSET_MSG(&agent_result))
			zbx_strlcpy(error, agent_result.msg, max_error_len);
		ret = FAIL;
	}
	else if (NULL != result && ISSET_TEXT(&agent_result))
		*result = zbx_strdup(*result, agent_result.text);

	zbx_alarm_off();

	free_result(&agent_result);

	zbx_free(item.key);
fail:
	zbx_free(port);
	zbx_free(param);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

static int	zbx_execute_script_on_terminal(const DC_HOST *host, const zbx_script_t *script, char **result,
		char *error, size_t max_error_len)
{
	int		ret = FAIL, i;
	AGENT_RESULT	agent_result;
	DC_ITEM		item;
	int             (*function)(DC_ITEM *, AGENT_RESULT *);

#if defined(HAVE_SSH2) || defined(HAVE_SSH)
	assert(ZBX_SCRIPT_TYPE_SSH == script->type || ZBX_SCRIPT_TYPE_TELNET == script->type);
#else
	assert(ZBX_SCRIPT_TYPE_TELNET == script->type);
#endif

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	*error = '\0';
	memset(&item, 0, sizeof(item));
	memcpy(&item.host, host, sizeof(item.host));

	for (i = 0; INTERFACE_TYPE_COUNT > i; i++)
	{
		if (SUCCEED == (ret = DCconfig_get_interface_by_type(&item.interface, host->hostid,
				INTERFACE_TYPE_PRIORITY[i])))
		{
			break;
		}
	}

	if (FAIL == ret)
	{
		zbx_snprintf(error, max_error_len, "No interface defined for host [%s]", host->host);
		goto fail;
	}

	switch (script->type)
	{
		case ZBX_SCRIPT_TYPE_SSH:
			item.authtype = script->authtype;
			item.publickey = script->publickey;
			item.privatekey = script->privatekey;
			ZBX_FALLTHROUGH;
		case ZBX_SCRIPT_TYPE_TELNET:
			item.username = script->username;
			item.password = script->password;
			break;
	}

#if defined(HAVE_SSH2) || defined(HAVE_SSH)
	if (ZBX_SCRIPT_TYPE_SSH == script->type)
	{
		item.key = zbx_dsprintf(item.key, "ssh.run[,,%s]", script->port);
		function = get_value_ssh;
	}
	else
	{
#endif
		item.key = zbx_dsprintf(item.key, "telnet.run[,,%s]", script->port);
		function = get_value_telnet;
#if defined(HAVE_SSH2) || defined(HAVE_SSH)
	}
#endif
	item.value_type = ITEM_VALUE_TYPE_TEXT;
	item.params = zbx_strdup(item.params, script->command);

	init_result(&agent_result);

	zbx_alarm_on(CONFIG_TIMEOUT);

	if (SUCCEED != (ret = function(&item, &agent_result)))
	{
		if (ISSET_MSG(&agent_result))
			zbx_strlcpy(error, agent_result.msg, max_error_len);
		ret = FAIL;
	}
	else if (NULL != result && ISSET_TEXT(&agent_result))
		*result = zbx_strdup(*result, agent_result.text);

	zbx_alarm_off();

	free_result(&agent_result);

	zbx_free(item.params);
	zbx_free(item.key);
fail:
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

static int	DBget_script_by_scriptid(zbx_uint64_t scriptid, zbx_script_t *script, zbx_uint64_t *groupid)
{
	int		ret = FAIL;
	DB_RESULT	result;
	DB_ROW		row;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	result = DBselect(
			"select type,execute_on,command,groupid,host_access,timeout"
			" from scripts"
			" where scriptid=" ZBX_FS_UI64,
			scriptid);

	if (NULL != (row = DBfetch(result)))
	{
		char	*tm;

		ZBX_STR2UCHAR(script->type, row[0]);
		ZBX_STR2UCHAR(script->execute_on, row[1]);
		script->command = zbx_strdup(script->command, row[2]);
		script->command_orig = zbx_strdup(script->command_orig, row[2]);
		ZBX_DBROW2UINT64(*groupid, row[3]);
		ZBX_STR2UCHAR(script->host_access, row[4]);
		tm = zbx_strdup(NULL, row[5]);

		ret = is_time_suffix(tm, &script->timeout, ZBX_LENGTH_UNLIMITED);

		zbx_free(tm);
	}
	DBfree_result(result);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

static int	check_script_permissions(zbx_uint64_t groupid, zbx_uint64_t hostid)
{
	DB_RESULT		result;
	int			ret = SUCCEED;
	zbx_vector_uint64_t	groupids;
	char			*sql = NULL;
	size_t			sql_alloc = 0, sql_offset = 0;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() groupid:" ZBX_FS_UI64 " hostid:" ZBX_FS_UI64, __func__, groupid, hostid);

	if (0 == groupid)
		goto exit;

	zbx_vector_uint64_create(&groupids);
	zbx_dc_get_nested_hostgroupids(&groupid, 1, &groupids);

	zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset,
			"select hostid"
			" from hosts_groups"
			" where hostid=" ZBX_FS_UI64
				" and",
			hostid);

	DBadd_condition_alloc(&sql, &sql_alloc, &sql_offset, "groupid", groupids.values,
			groupids.values_num);

	result = DBselect("%s", sql);

	zbx_free(sql);
	zbx_vector_uint64_destroy(&groupids);

	if (NULL == DBfetch(result))
		ret = FAIL;

	DBfree_result(result);
exit:
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

static int	check_user_permissions(zbx_uint64_t userid, const DC_HOST *host, zbx_script_t *script)
{
	int		ret = SUCCEED;
	DB_RESULT	result;
	DB_ROW		row;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() userid:" ZBX_FS_UI64 " hostid:" ZBX_FS_UI64 " scriptid:" ZBX_FS_UI64,
			__func__, userid, host->hostid, script->scriptid);

	result = DBselect(
		"select null"
			" from hosts_groups hg,rights r,users_groups ug"
		" where hg.groupid=r.id"
			" and r.groupid=ug.usrgrpid"
			" and hg.hostid=" ZBX_FS_UI64
			" and ug.userid=" ZBX_FS_UI64
		" group by hg.hostid"
		" having min(r.permission)>%d"
			" and max(r.permission)>=%d",
		host->hostid,
		userid,
		PERM_DENY,
		script->host_access);

	if (NULL == (row = DBfetch(result)))
		ret = FAIL;

	DBfree_result(result);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

void	zbx_script_init(zbx_script_t *script)
{
	memset(script, 0, sizeof(zbx_script_t));
}

void	zbx_script_clean(zbx_script_t *script)
{
	zbx_free(script->port);
	zbx_free(script->username);
	zbx_free(script->publickey);
	zbx_free(script->privatekey);
	zbx_free(script->password);
	zbx_free(script->command);
	zbx_free(script->command_orig);
}

static int	zbx_get_event_by_eventid(zbx_uint64_t eventid, DB_EVENT **event_out)
{
	int			ret = SUCCEED;
	zbx_vector_ptr_t	events;
	zbx_vector_uint64_t	eventids;

	zbx_vector_ptr_create(&events);
	zbx_vector_uint64_create(&eventids);
	zbx_vector_uint64_append(&eventids, eventid);

	zbx_db_get_events_by_eventids(&eventids, &events);

	if (0 < events.values_num)
		*event_out = (DB_EVENT*)events.values[0];
	else
		ret = FAIL;

	zbx_vector_ptr_destroy(&events);
	zbx_vector_uint64_destroy(&eventids);

	return ret;
}

/***********************************************************************************
 *                                                                                 *
 * Function: zbx_script_prepare                                                    *
 *                                                                                 *
 * Purpose: prepares user script                                                   *
 *                                                                                 *
 * Parameters: script        - [IN] the script to prepare                          *
 *             host          - [IN] the host the script will be executed on        *
 *             user          - [IN] the user executing script (can be NULL)        *
 *             ctx           - [IN] the execution context of a script              *
 *             eventid       - [IN] the eventid for macro resolving                *
 *             error         - [OUT] the error message buffer                      *
 *             max_error_len - [IN] the size of error message output buffer        *
 *             event         - [IN/OUT] the event for the execution (can be NULL)  *
 *                                                                                 *
 * Return value:  SUCCEED - the script has been prepared successfully              *
 *                FAIL    - otherwise, error contains error message                *
 *                                                                                 *
 * Comments: This function prepares script for execution by loading global         *
 *           script/expanding macros.                                              *
 *           Prepared scripts must be always freed with zbx_script_clean()         *
 *           function.                                                             *
 *                                                                                 *
 ***********************************************************************************/
int	zbx_script_prepare(zbx_script_t *script, const DC_HOST *host, const zbx_user_t *user,
		zbx_script_exec_context ctx, zbx_uint64_t eventid, char *error, size_t max_error_len,
		DB_EVENT **event)
{
	int			macro_mask, ret = FAIL;
	zbx_uint64_t		groupid, userid, *p_userid = NULL;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	switch (script->type)
	{
		case ZBX_SCRIPT_TYPE_SSH:
			substitute_simple_macros(NULL, NULL, NULL, NULL, &host->hostid, NULL, NULL, NULL, NULL, NULL,
					&script->publickey, MACRO_TYPE_COMMON, NULL, 0);
			substitute_simple_macros(NULL, NULL, NULL, NULL, &host->hostid, NULL, NULL, NULL, NULL, NULL,
					&script->privatekey, MACRO_TYPE_COMMON, NULL, 0);
			ZBX_FALLTHROUGH;
		case ZBX_SCRIPT_TYPE_TELNET:
			substitute_simple_macros(NULL, NULL, NULL, NULL, &host->hostid, NULL, NULL, NULL, NULL, NULL,
					&script->port, MACRO_TYPE_COMMON, NULL, 0);

			if ('\0' != *script->port && SUCCEED != (ret = is_ushort(script->port, NULL)))
			{
				zbx_snprintf(error, max_error_len, "Invalid port number \"%s\"", script->port);
				goto out;
			}

			substitute_simple_macros_unmasked(NULL, NULL, NULL, NULL, &host->hostid, NULL, NULL, NULL, NULL,
					NULL, &script->username, MACRO_TYPE_COMMON, NULL, 0);
			substitute_simple_macros_unmasked(NULL, NULL, NULL, NULL, &host->hostid, NULL, NULL, NULL, NULL,
					NULL, &script->password, MACRO_TYPE_COMMON, NULL, 0);
			break;
		case ZBX_SCRIPT_TYPE_CUSTOM_SCRIPT:
			dos2unix(script->command);	/* CR+LF (Windows) => LF (Unix) */
			ZBX_FALLTHROUGH;
		case ZBX_SCRIPT_TYPE_WEBHOOK:
			macro_mask = MACRO_TYPE_SCRIPT;

			if ((ZBX_SCRIPT_CTX_EVENT == ctx && FAIL != zbx_get_event_by_eventid(eventid, event)) ||
					ZBX_SCRIPT_CTX_ACTION == ctx)
			{
				macro_mask |= (MACRO_TYPE_MESSAGE_ACK | MACRO_TYPE_MESSAGE_NORMAL |
						MACRO_TYPE_MESSAGE_RECOVERY);
			}

			if (NULL != user)
			{
				/* Make a copy to preserve const-correctness. */
				userid = user->userid;
				p_userid = &userid;
			}

			if (SUCCEED != substitute_simple_macros_unmasked(NULL, (event != NULL ? *event : NULL), NULL,
					p_userid, NULL, host, NULL, NULL, NULL, NULL, &script->command, macro_mask,
					error, max_error_len))
			{
				goto out;
			}

			if (SUCCEED != substitute_simple_macros(NULL, (event != NULL ? *event : NULL), NULL, p_userid,
					NULL, host, NULL, NULL, NULL, NULL, &script->command_orig, macro_mask,
					error, max_error_len))
			{
				THIS_SHOULD_NEVER_HAPPEN;
			}

			break;
		case ZBX_SCRIPT_TYPE_GLOBAL_SCRIPT:
			if (SUCCEED != DBget_script_by_scriptid(script->scriptid, script, &groupid))
			{
				zbx_strlcpy(error, "Unknown script identifier.", max_error_len);
				goto out;
			}

			if (ZBX_SCRIPT_TYPE_WEBHOOK == script->type && ZBX_SCRIPT_CTX_HOST != ctx)
			{
				if (user != NULL && USER_TYPE_SUPER_ADMIN != user->type)
				{
					zbx_strlcpy(error, "Cannot determine permission of a script.",
							max_error_len);
					goto out;
				}
				else
					goto skip_perm_check;
			}

			if (groupid > 0 && SUCCEED != check_script_permissions(groupid, host->hostid))
			{
				zbx_strlcpy(error, "Script does not have permission to be executed on the host.",
						max_error_len);
				goto out;
			}

			if (user != NULL && USER_TYPE_SUPER_ADMIN != user->type &&
					SUCCEED != check_user_permissions(user->userid, host, script))
			{
				zbx_strlcpy(error, "User does not have permission to execute this script on the host.",
						max_error_len);
				goto out;
			}
skip_perm_check:
			if (NULL != user)
			{
				/* zbx_script_prepare() receives 'user' as const-pointer but */
				/* substitute_simple_macros() takes 'userid' as non-const pointer. */
				/* Make a copy to preserve const-correctness. */
				userid = user->userid;
				p_userid = &userid;
			}

			if (SUCCEED != substitute_simple_macros_unmasked(NULL, NULL, NULL, p_userid, NULL, host,
					NULL, NULL, NULL, NULL, &script->command, MACRO_TYPE_SCRIPT, error,
					max_error_len))
			{
				goto out;
			}

			/* expand macros in command_orig used for non-secure logging */
			if (SUCCEED != substitute_simple_macros(NULL, NULL, NULL, p_userid, NULL, host, NULL,
					NULL, NULL, NULL, &script->command_orig, MACRO_TYPE_SCRIPT, error,
					max_error_len))
			{
				/* script command_orig is a copy of script command - if the script command  */
				/* macro substitution succeeded, then it will succeed also for command_orig */
				THIS_SHOULD_NEVER_HAPPEN;
			}

			if (ZBX_SCRIPT_TYPE_GLOBAL_SCRIPT == script->type)
			{
				/* DBget_script_by_scriptid() may overwrite type with anything but global script */
				/* ... therefore this recursion is no more than two layers deep */
				THIS_SHOULD_NEVER_HAPPEN;
				goto out;
			}

			if (FAIL == zbx_script_prepare(script, host, user, ctx, eventid, error, max_error_len, event))
				goto out;

			break;
		case ZBX_SCRIPT_TYPE_IPMI:
			break;
		default:
			zbx_snprintf(error, max_error_len, "Invalid command type \"%d\".", (int)script->type);
			goto out;
	}

	ret = SUCCEED;
out:
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));
	return ret;
}

/**************************************************************************************************
 *                                                                                                *
 * Function: DBfetch_webhook_params                                                               *
 *                                                                                                *
 * Purpose: fetch webhook parameters and expand macros inside them                                *
 *                                                                                                *
 * Parameters:  script         - [IN] the script to be executed                                   *
 *              host           - [IN] the host the script will be executed on                     *
 *              event          - [IN] the event for the execution case                            *
 *              user           - [IN] the user executing script (can be NULL)                     *
 *              ctx            - [IN] the script execution context                                *
 *              params         - [OUT] parsed parameters with expanded macros                     *
 *                                                                                                *
 * Return value:  SUCCEED - processed successfully                                                *
 *                FAIL - an error occurred                                                        *
 *                                                                                                *
 **************************************************************************************************/
static int	DBfetch_webhook_params(const zbx_script_t *script, const DC_HOST *host, const DB_EVENT *event,
		const zbx_user_t *user, zbx_script_exec_context ctx, char **params)
{
	int		ret = SUCCEED;
	zbx_uint64_t	userid, *p_userid = NULL;
	char		error[MAX_STRING_LEN];
	DB_RESULT	result;
	DB_ROW		row;
	struct zbx_json	json_data;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	result = DBselect("select name,value from script_param where scriptid=" ZBX_FS_UI64, script->scriptid);

	if (NULL == result)
	{
		ret = FAIL;
		goto out;
	}

	zbx_json_init(&json_data, ZBX_JSON_STAT_BUF_LEN);

	while (NULL != (row = DBfetch(result)))
	{
		char	*name, *value;

		name = zbx_strdup(NULL, row[0]);
		value = zbx_strdup(NULL, row[1]);
		zbx_json_addstring(&json_data, name, value, ZBX_JSON_TYPE_STRING);
		zbx_free(name);
		zbx_free(value);
	}

	zbx_json_close(&json_data);

	if (NULL != user)
	{
		userid = user->userid;
		p_userid = &userid;
	}

	*params = zbx_strdup(NULL, json_data.buffer);

	if (SUCCEED != substitute_simple_macros_unmasked(NULL, NULL, NULL, p_userid, NULL, host, NULL, NULL, NULL,
			NULL, params, MACRO_TYPE_SCRIPT, error, sizeof(error)))
	{
		zabbix_log(LOG_LEVEL_WARNING, "failed to expand macros for script '%s'", script->command_orig);
	}

	if (ZBX_SCRIPT_CTX_EVENT == ctx)
	{
		if (SUCCEED != substitute_simple_macros_unmasked(NULL, event, NULL, p_userid, NULL, host, NULL, NULL,
				NULL, NULL, params, (MACRO_TYPE_MESSAGE_ACK | MACRO_TYPE_MESSAGE_NORMAL |
				MACRO_TYPE_MESSAGE_RECOVERY), error, sizeof(error)))
		{
			zabbix_log(LOG_LEVEL_WARNING, "failed to expand macros for script '%s'", script->command_orig);
		}
	}

	zbx_json_free(&json_data);
out:
	DBfree_result(result);
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

/**************************************************************************************************
 *                                                                                                *
 * Function: zbx_execute_webhook                                                                  *
 *                                                                                                *
 * Purpose: executes webhook                                                                      *
 *                                                                                                *
 * Parameters:  script         - [IN] the script to be executed                                   *
 *              host           - [IN] the host the script will be executed on                     *
 *              event          - [IN] the event for the execution case                            *
 *              ctx            - [IN] the script execution context                                *
 *              user           - [IN] the user executing script (can be NULL)                     *
 *              error          - [IN/OUT] the error reported by the script (or the script engine) *
 *              max_error_len  - [IN] the maximum error length                                    *
 *              result         - [OUT] the result of a script execution                           *
 *              debug          - [OUT] the debug data (optional)                                  *
 *                                                                                                *
 * Return value:  SUCCEED - processed successfully                                                *
 *                FAIL - an error occurred                                                        *
 *                                                                                                *
 **************************************************************************************************/
static int	zbx_execute_webhook(const zbx_script_t *script, const DC_HOST *host, const DB_EVENT *event,
		zbx_script_exec_context ctx, const zbx_user_t *user, char *error, size_t max_error_len, char **result,
		char **debug)
{
	int	ret;
	char	*params;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	if (FAIL == DBfetch_webhook_params(script, host, event, user, ctx, &params))
	{
		zabbix_log(LOG_LEVEL_WARNING, "failed to fetch script parameters for script id " ZBX_FS_UI64,
				script->scriptid);
	}

	if (NULL != event)
		zbx_clean_event((DB_EVENT*)event);

	ret = zbx_es_execute_command(script->command, params, script->timeout, result, error, max_error_len, debug);

	zbx_free(params);
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_script_execute                                               *
 *                                                                            *
 * Purpose: executing user scripts or remote commands                         *
 *                                                                            *
 * Parameters:  script         - [IN] the script to be executed               *
 *              host           - [IN] the host the script will be executed on *
 *              user           - [IN] the user executing script (can be NULL) *
 *              event          - [IN] the event for the execution case        *
 *              ctx            - [IN] the script execution context            *
 *              result         - [OUT] the result of a script execution       *
 *              error          - [OUT] the error reported by the script       *
 *              max_error_len  - [IN] the maximum error length                *
 *              debug          - [OUT] the debug data (optional)              *
 *                                                                            *
 * Return value:  SUCCEED - processed successfully                            *
 *                FAIL - an error occurred                                    *
 *                TIMEOUT_ERROR - a timeout occurred                          *
 *                                                                            *
 ******************************************************************************/
int	zbx_script_execute(const zbx_script_t *script, const DC_HOST *host, const zbx_user_t *user, const DB_EVENT *event,
		zbx_script_exec_context ctx, char **result, char *error, size_t max_error_len, char **debug)
{
	int	ret = FAIL;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	*error = '\0';

	switch (script->type)
	{
		case ZBX_SCRIPT_TYPE_WEBHOOK:
			ret = zbx_execute_webhook(script, host, event, ctx, user, error, max_error_len, result, debug);
			break;
		case ZBX_SCRIPT_TYPE_CUSTOM_SCRIPT:
			switch (script->execute_on)
			{
				case ZBX_SCRIPT_EXECUTE_ON_AGENT:
					ret = zbx_execute_script_on_agent(host, script->command, result, error,
							max_error_len);
					break;
				case ZBX_SCRIPT_EXECUTE_ON_SERVER:
				case ZBX_SCRIPT_EXECUTE_ON_PROXY:
					ret = zbx_execute(script->command, result, error, max_error_len,
							CONFIG_TRAPPER_TIMEOUT, ZBX_EXIT_CODE_CHECKS_ENABLED, NULL);
					break;
				default:
					zbx_snprintf(error, max_error_len, "Invalid 'Execute on' option \"%d\".",
							(int)script->execute_on);
			}
			break;
		case ZBX_SCRIPT_TYPE_IPMI:
#ifdef HAVE_OPENIPMI
			if (0 == CONFIG_IPMIPOLLER_FORKS)
			{
				zbx_strlcpy(error, "Cannot perform IPMI request: configuration parameter"
						" \"StartIPMIPollers\" is 0.", max_error_len);
				break;
			}

			if (SUCCEED == (ret = zbx_ipmi_execute_command(host, script->command, error, max_error_len)))
			{
				if (NULL != result)
					*result = zbx_strdup(*result, "IPMI command successfully executed.");
			}
#else
			zbx_strlcpy(error, "Support for IPMI commands was not compiled in.", max_error_len);
#endif
			break;
		case ZBX_SCRIPT_TYPE_SSH:
#if !defined(HAVE_SSH2) && !defined(HAVE_SSH)
			zbx_strlcpy(error, "Support for SSH script was not compiled in.", max_error_len);
			break;
#endif
		case ZBX_SCRIPT_TYPE_TELNET:
			ret = zbx_execute_script_on_terminal(host, script, result, error, max_error_len);
			break;
		default:
			zbx_snprintf(error, max_error_len, "Invalid command type \"%d\".", (int)script->type);
	}

	if (SUCCEED != ret && NULL != result)
		*result = zbx_strdup(*result, "");

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_script_create_task                                           *
 *                                                                            *
 * Purpose: creates remote command task from a script                         *
 *                                                                            *
 * Return value:  the identifier of the created task or 0 in the case of      *
 *                error                                                       *
 *                                                                            *
 ******************************************************************************/
zbx_uint64_t	zbx_script_create_task(const zbx_script_t *script, const DC_HOST *host, zbx_uint64_t alertid, int now)
{
	zbx_tm_task_t	*task;
	unsigned short	port;
	zbx_uint64_t	taskid;

	if (NULL != script->port && '\0' != script->port[0])
		is_ushort(script->port, &port);
	else
		port = 0;

	DBbegin();

	taskid = DBget_maxid("task");

	task = zbx_tm_task_create(taskid, ZBX_TM_TASK_REMOTE_COMMAND, ZBX_TM_STATUS_NEW, now,
			ZBX_REMOTE_COMMAND_TTL, host->proxy_hostid);

	task->data = zbx_tm_remote_command_create(script->type, script->command, script->execute_on, port,
			script->authtype, script->username, script->password, script->publickey, script->privatekey,
			taskid, host->hostid, alertid);

	if (FAIL == zbx_tm_save_task(task))
		taskid = 0;

	DBcommit();

	zbx_tm_task_free(task);

	return taskid;
}
