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
#define LOGIN_LIMIT 100
#define AGE_LIMIT 10

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

    signal(SIGINT, SIG_IGN);
	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;
    int i = 0;
	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);
        for(i=0; i < LENGTH; i++){
            if(user[i] == '\n'){
                user[i] = '\0';
                break;
            }
        }

	    user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
            if(passwddata->pwfailed > LOGIN_LIMIT){
                printf("Your account has been suspended, contact the administrator\n");
                return 0;
            }
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
            user_pass = crypt(user_pass, passwddata->passwd_salt);
			if (!strcmp(user_pass, passwddata->passwd)) {
                if(passwddata->pwfailed != 0){
                    printf(" *** WARNING! *** Failed attemps since last login: %d\n", passwddata->pwfailed);
                    passwddata->pwfailed = 0;
                }
                passwddata->pwage++;
                if(passwddata->pwage > AGE_LIMIT){
                    printf(" *** WARNING! *** Your password is getting old, like Gandalf!\n");
                }
                mysetpwent(user, passwddata);
				printf(" You're in !\n");

                setuid(passwddata->uid);
                execl("/bin/sh", "sh", NULL);
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

			} else {
                printf("Login Incorrect \n");
                passwddata->pwfailed++;
                mysetpwent(user, passwddata);
            }
		} else {
            printf("Login Incorrect \n");
        }
	}
	return 0;
}

