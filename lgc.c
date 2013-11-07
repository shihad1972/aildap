#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct cont_s {
	char *domain, *dc, *dn, *name;
	short int action, group;
} cont_s;

enum {
	NONE = 0,
	ONE,
	INSERT,
	REMOVE,
	MALLOC,
	WARG,
	NODOM,
	NOGRP,
	NAME = 32,
	DC = 64,
	DNL = 67,
	DOMAIN = 256,
	DN = 512
};

void
rep_error(const char *error)
{
	fprintf(stderr, "Cannot allocate memory for %s\n", error);
	exit(MALLOC);
}

void
init_data_struct(cont_s *data)
{
	data->domain = '\0';
	data->dc = '\0';
	data->dn = '\0';
	data->name = '\0';
	data->action = 0;
	data->group = 0;
	if (!(data->domain = calloc(ONE, DOMAIN)))
		rep_error("domain in data");
	if (!(data->dc = calloc(ONE, DC)))
		rep_error("dc in data");
	if (!(data->dn = calloc(ONE, DN)))
		rep_error("dn in data");
	if (!(data->name = calloc(ONE, NAME)))
		rep_error("group in data");
}

void
clean_data(cont_s *data)
{
	if (data->domain)
		free(data->domain);
	if (data->dc)
		free(data->dc);
	if (data->dn)
		free(data->dn);
	if (data->name)
		free(data->name);
	if (data)
		free(data);
}

int
parse_command_line(int argc, char *argv[], cont_s *data)
{
	int retval = NONE, opt = NONE;

	while ((opt = getopt(argc, argv, "d:g:n:")) != -1) {
		if (opt == 'd') {
			if ((retval = snprintf(data->domain, DOMAIN, "%s", optarg)) > DOMAIN) {
				fprintf(stderr, "Domain truncated!\n");
				fprintf(stderr, "Max 255 characters in a domain name\n");
			}
			retval = NONE;
		} else if (opt == 'n') {
			if ((retval = snprintf(data->name, NAME, "%s", optarg)) > NAME) {
				fprintf(stderr, "Name truncated!\n");
				fprintf(stderr, "Max %d characters in a group name\n", NAME);
			}
			retval = NONE;
/*		} else if (opt == 'i') {
			data->action = INSERT;
		} else if (opt == 'r') {
			data->action = REMOVE; */
		} else if (opt == 'g') {
			data->group = (short)strtoul(optarg, NULL, 10);
		} else {
			fprintf(stderr, "Usage: %s [ -i | -r ] -d domain-name -g gid\n", argv[0]);
			return WARG;
		}
	}
	if (strlen(data->domain) == 0) {
		fprintf(stderr, "No domain specified\n");
		retval = NODOM;
	} else if (data->group == 0) {
		fprintf(stderr, "No group specified\n");
		retval = NOGRP;
	}
	return retval;
}

void
convert_to_dn(cont_s *data)
{
	char dom[DOMAIN], *tmp = '\0', *dtmp = '\0', *dntmp = '\0';
	int dot = '.', retval = NONE;
	size_t len;

	snprintf(dom, DOMAIN, "%s", data->domain);
	dntmp = data->dn;
	dtmp = dom;
	while ((tmp = strchr(dtmp, dot))) {
		*tmp = '\0';
		if (dtmp == dom) {
			if ((retval = snprintf(data->dc, DC, "%s", dom)) > DC)
				fprintf(stderr, "DC Truncated! Only allowed %d characters\n", DC);
		}
		retval = snprintf(dntmp, DNL, "dc=%s,", dtmp);
		dntmp += retval;
		dtmp = tmp + 1;
	}
	len = strlen(data->dn);
	dntmp = data->dn + len;
	snprintf(dntmp, DNL, "dc=%s", dtmp);
}

void
output_insert_cont(cont_s *data)
{
	if (!(data))
		return;
	char *grp = data->name, *dn = data->dn;
	short int gid = data->group;
	printf("\
# %s, group, %s\n\
dn: cn=%s,ou=group,%s\n\
cn: %s\n\
gidNumber: %hd\n\
objectClass: posixGroup\n\
objectClass: top\n", grp, data->domain, grp, dn, grp, gid);
}
/*
void
output_remove_cont(cont_s *data)
{
	if (!(data))
		return;
	char *grp = data->name, *dn = data->dn;
}
*/
int
main(int argc, char *argv[])
{
	int retval = NONE;
	cont_s *data;

	if (!(data = calloc(ONE, sizeof(cont_s))))
		rep_error("data");
	init_data_struct(data);
	if ((retval = parse_command_line(argc, argv, data)) != 0) {
		clean_data(data);
		return retval;
	}
	convert_to_dn(data); /*
	if (data->action == NONE) {
		fprintf(stderr, "No action specified. Assuming insert\n");
		output_insert_cont(data);
	} else if (data->action == INSERT) { */
		output_insert_cont(data);
/*	} else if (data->action == REMOVE) {
		output_remove_cont(data); 
	} else {
		fprintf(stderr, "Unknown action %d\n", data->action);
	} */
	clean_data(data);
	return retval;
}