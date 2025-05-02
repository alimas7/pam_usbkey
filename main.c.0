#include <stdio.h>
#include <security/pam_appl.h>

int main (int argc, char *argv[])
{
/* int pam_start_confdir(const char *service_name, const char *user, const struct pam_conv *pam_conversation, const char *confdir, pam_handle_t **pamh); */

  struct pam_conv  pamC;
  pam_handle_t    *pamH;
  int              r;

  r = pam_start_confdir("sudo", "neo", &pamC, "/tmp/td1", &pamH);

  printf("pam_start_confdir() returned: %d\n", r);

  r = pam_authenticate(pamH, 0);

  printf("pam_authenticate() returned: %d\n", r);

  r = pam_end(pamH, r);

  printf("pam_end() returned: %d\n", r);
}
