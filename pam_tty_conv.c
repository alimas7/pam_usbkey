/* https://docs.oracle.com/cd/E19253-01/816-4863/emrbk/index.html
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved. 
 * Use is subject to license terms. 
 */
 
#pragma ident	"@(#)pam_tty_conv.c	1.4	05/02/12 SMI"  

#define	__EXTENSIONS__	/* to expose flockfile and friends in stdio.h */ 
#include <errno.h>
#include <libgen.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
/*#include <stropts.h>*/
#include <string.h>
#include <unistd.h>
#include <termio.h>
#include <security/pam_appl.h>

static int ctl_c;	/* was the conversation interrupted? */

/* ARGSUSED 1 */
static void
interrupt(int x)
{
	ctl_c = 1;
}

/* getinput -- read user input from stdin abort on ^C
 *	Entry	noecho == TRUE, don't echo input.
 *	Exit	User's input.
 *		If interrupted, send SIGINT to caller for processing.
 */
static char *
getinput(int noecho)
{
	struct termio tty;
	unsigned short tty_flags;
	char input[PAM_MAX_RESP_SIZE];
	int c;
	int i = 0;
	void (*sig)(int);

	ctl_c = 0;
	sig = signal(SIGINT, interrupt);
	if (noecho) {
		(void) ioctl(fileno(stdin), TCGETA, &tty);
		tty_flags = tty.c_lflag;
		tty.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
		(void) ioctl(fileno(stdin), TCSETAF, &tty);
	}

	/* go to end, but don't overflow PAM_MAX_RESP_SIZE */
	flockfile(stdin);
	while (ctl_c == 0 &&
	    (c = getchar_unlocked()) != '\n' &&
	    c != '\r' &&
	    c != EOF) {
		if (i < PAM_MAX_RESP_SIZE) {
			input[i++] = (char)c;
		}
	}
	funlockfile(stdin);
	input[i] = '\0';
	if (noecho) {
		tty.c_lflag = tty_flags;
		(void) ioctl(fileno(stdin), TCSETAW, &tty);
		(void) fputc('\n', stdout);
	}
	(void) signal(SIGINT, sig);
	if (ctl_c == 1)
		(void) kill(getpid(), SIGINT);

	return (strdup(input));
}

/* Service modules do not clean up responses if an error is returned.
 * Free responses here.
 */
static void
free_resp(int num_msg, struct pam_response *pr)
{
	int i;
	struct pam_response *r = pr;

	if (pr == NULL)
		return;

	for (i = 0; i < num_msg; i++, r++) {

		if (r->resp) {
			/* clear before freeing -- may be a password */
			bzero(r->resp, strlen(r->resp));
			free(r->resp);
			r->resp = NULL;
		}
	}
	free(pr);
}

/* ARGSUSED */
int
pam_tty_conv(int num_msg, struct pam_message **mess,
    struct pam_response **resp, void *my_data)
{
	struct pam_message *m = *mess;
	struct pam_response *r;
	int i;

	if (num_msg <= 0 || num_msg >= PAM_MAX_NUM_MSG) {
		(void) fprintf(stderr, "bad number of messages %d "
		    "<= 0 || >= %d\n",
		    num_msg, PAM_MAX_NUM_MSG);
		*resp = NULL;
		return (PAM_CONV_ERR);
	}
	if ((*resp = r = calloc(num_msg,
	    sizeof (struct pam_response))) == NULL)
		return (PAM_BUF_ERR);

	/* Loop through messages */
	for (i = 0; i < num_msg; i++) {
		int echo_off;

		/* bad message from service module */
		if (m->msg == NULL) {
			(void) fprintf(stderr, "message[%d]: %d/NULL\n",
			    i, m->msg_style);
			goto err;
		}

		/*
		 * fix up final newline:
		 * 	removed for prompts
		 * 	added back for messages
		 */
/*
		if (m->msg[strlen(m->msg)] == '\n')
			m->msg[strlen(m->msg)] = '\0';
*/

		r->resp = NULL;
		r->resp_retcode = 0;
		echo_off = 0;
		switch (m->msg_style) {

		case PAM_PROMPT_ECHO_OFF:
			echo_off = 1;
			/*FALLTHROUGH*/

		case PAM_PROMPT_ECHO_ON:
			(void) fputs(m->msg, stdout);

			r->resp = getinput(echo_off);
			break;

		case PAM_ERROR_MSG:
			(void) fputs(m->msg, stderr);
			(void) fputc('\n', stderr);
			break;

		case PAM_TEXT_INFO:
			(void) fputs(m->msg, stdout);
			(void) fputc('\n', stdout);
			break;

		default:
			(void) fprintf(stderr, "message[%d]: unknown type "
			    "%d/val=\"%s\"\n",
			    i, m->msg_style, m->msg);
			/* error, service module won't clean up */
			goto err;
		}
		if (errno == EINTR)
			goto err;

		/* next message/response */
		m++;
		r++;
	}
	return (PAM_SUCCESS);

err:
	free_resp(i, r);
	*resp = NULL;
	return (PAM_CONV_ERR);
}
