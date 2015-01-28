/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"
/* Uncomment next line in step 2 */
/* #include "pwent.h" */

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define LOGIN_LIMIT 1000
#define AGE_LIMIT 10

int main(int argc, char *argv[]) {

    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

	mypwent *passwddata;

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char prompt[] = "password: ";
	char *user_pass;

    int i = 0;

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

        /* user fgets to avoid buffer overflow attacks */
		if (fgets(user, LENGTH, stdin) == NULL)
			exit(0);

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

        /* Make sure that line ends with \0 so we can search for username. */
        for(i=0; i < LENGTH; i++){
            if(user[i] == '\n'){
                user[i] = '\0';
                break;
            }
        }

	    user_pass = getpass(prompt);
        /* Changed to use mygetpwnam instead of default mygetpwnam */
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
            /* If login limit is reached, notify user and end login process */
            if(passwddata->pwfailed > LOGIN_LIMIT){
                printf("Your account has been suspended, contact the administrator\n");
                return 0;
            }
            /* Encrypt the password entered by the user and validate with the user data */
            user_pass = crypt(user_pass, passwddata->passwd_salt);

            if(!user_pass){
                /*Crypt failed, exit login shell */
                printf("Crypt failed, contact the administrator\n");
                return 0;
            }

			if (!strcmp(user_pass, passwddata->passwd)) {
                /* If there has been failed login attempts notify the user */
                if(passwddata->pwfailed != 0){
                    printf(" *** WARNING! *** Failed attemps since last login: %d\n", passwddata->pwfailed);
                    passwddata->pwfailed = 0;
                }
                /* If password has reached its age notify the user */
                passwddata->pwage++;
                if(passwddata->pwage > AGE_LIMIT){
                    printf(" *** WARNING! *** Your password is getting old, like Gandalf!\n");
                }

                /* Update the user login data (e.g pwfailed reset) */
                mysetpwent(user, passwddata);
				printf(" You're in !\n");

                /* Lower the rights of the program to the user privilege level */
                if(setuid(passwddata->uid) == 0){
                    /* Start shell */
                    execl("/bin/sh", "sh", NULL);
                }
                /* Setuid failed*/
                printf("Setuid failed, contact the administrator\n");
                return 0;
			} else {
                /* If bad password, increase pwfailed counter */
                passwddata->pwfailed++;
                mysetpwent(user, passwddata);
            }
		}
        /* Notify user about incorrect login information. */
        printf("Login Incorrect \n");
        sleep(1);
	}
	return 0;
}

