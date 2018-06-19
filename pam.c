/*
 * pam.c
 *
 *  Created on: 13.06.2018
 *      Author: jan
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <pwd.h>
#include <paths.h>

#include <smlog.h>

#include "pam.h"

#define SERVICE_NAME	"display-manager"

#define err(name) 															\
	do { 																	\
		smlog("[ %s ]\tpid=%d\t%s:%d:\t\t\t%s %s\n", SMLOGLVL_ERR, getpid(), __FILE__, __LINE__, name, pam_strerror(pam_handle, result)); \
		end(result); 														\
		return false;														\
	} while(1); 															\

static void init_env(struct passwd *pw);
static void set_env(char *name, char *value);
static int end(int last_result);
static int conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);

static pam_handle_t *pam_handle;

bool login(const char *username, const char* password, pid_t *child_pid)
{
	const char *data[2] = { username, password };
	struct pam_conv pam_conv = {
			conv, data
	};

	int result = pam_start(SERVICE_NAME, username, &pam_conv, &pam_handle);

	if(result != PAM_SUCCESS)
		err("pam_start");

	result = pam_authenticate(pam_handle, 0);
	if(result != PAM_SUCCESS)
		err("pam_authenticate");

	result = pam_acct_mgmt(pam_handle, PAM_ESTABLISH_CRED);
	if(result != PAM_SUCCESS)
		err("pam_act_mgmt");

	result = pam_setcred(pam_handle, 0);
	if(result != PAM_SUCCESS)
		err("pam_setcred");

	result = pam_open_session(pam_handle, 0);
	if(result != PAM_SUCCESS)
	{
		pam_setcred(pam_handle, PAM_DELETE_CRED);
		err("pam_open_session");
	}

	struct passwd *pw = getpwnam(username);
	init_env(pw);

	*child_pid = fork();
	if(*child_pid == 0)
	{
		chdir(pw->pw_dir);

		char *cmd = "exec /bin/bash --login /home/jan/nubix-workspace/xinitrc";
		execl(pw->pw_shell, pw->pw_shell, "-c", cmd, NULL);
		printf("Failed to start window manager");
		exit(EXIT_FAILURE);
	}

	return true;
}

bool logout()
{
	int result = pam_close_session(pam_handle, 0);
	if(result != PAM_SUCCESS)
	{
		pam_setcred(pam_handle, PAM_DELETE_CRED);
		err("pam_close_session");
	}

	end(result);
	return true;
}

static int conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    int i;

    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (*resp == NULL) {
        return PAM_BUF_ERR;
    }

    int result = PAM_SUCCESS;
    for (i = 0; i < num_msg; i++) {
        char *username, *password;
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_ON:
            username = ((char **) appdata_ptr)[0];
            (*resp)[i].resp = strdup(username);
            break;
        case PAM_PROMPT_ECHO_OFF:
            password = ((char **) appdata_ptr)[1];
            (*resp)[i].resp = strdup(password);
            break;
        case PAM_ERROR_MSG:
            fprintf(stderr, "%s\n", msg[i]->msg);
            result = PAM_CONV_ERR;
            break;
        case PAM_TEXT_INFO:
            printf("%s\n", msg[i]->msg);
            break;
        }
        if (result != PAM_SUCCESS) {
            break;
        }
    }

    if (result != PAM_SUCCESS) {
        free(*resp);
        *resp = 0;
    }

    return result;
}

static int end(int last_result)
{
	int result = pam_end(pam_handle, last_result);
	pam_handle = 0;
	return result;
}

static void set_env(char *name, char *value)
{
	unsigned long int name_val_len = strlen(name) + strlen(value) + 2;
	char *name_val = (char *) malloc(name_val_len);

	snprintf(name_val, name_val_len, "%s=%s", name, value);
	pam_putenv(pam_handle, name_val);
	free(name_val);
}

static void init_env(struct passwd *pw)
{
	set_env("HOME", pw->pw_dir);
	set_env("PWD", pw->pw_dir);
	set_env("SHELL", pw->pw_shell);
	set_env("USER", pw->pw_name);
	set_env("PATH", "/usr/local/bin:/usr/local/sbin:/usr/bin");
	set_env("MAIL", _PATH_MAILDIR);

	unsigned long int xauthority_len = strlen(pw->pw_dir) + strlen("/.Xauthority") + 1;
	char *xauthority = malloc(xauthority_len);
	snprintf(xauthority, xauthority_len, "%s/.Xauthority", pw->pw_dir);
	set_env("XAUTHORITY", xauthority);
	free(xauthority);
}
