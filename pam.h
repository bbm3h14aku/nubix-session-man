/*
 * pam.h
 *
 *  Created on: 13.06.2018
 *      Author: jan
 */

#ifndef PAM_H_
#define PAM_H_

#include <stdbool.h>

bool login(const char *username, const char *password, pid_t *child_pid);
bool logout();

#endif /* PAM_H_ */
