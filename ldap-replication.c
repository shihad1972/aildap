#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct lrc_t {
	char *host, *domain, *user, *db, *ca;
	short int ssl, tls;
} lrc_t;

enum {
	NONE = 0,
	ONE,
	MALLOC,
	WARG,
	NODOM,
	NOGRP,
	NOGRNM,
	NODATA,
	DB = 8,
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
rep_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s -d domain-name -h host -u user\
 -b db-number [-s | -t ] [ -c ca-cert-path]\n", prog);
}

void
rep_truncate(const char *what, int max)
{
	fprintf(stderr, "%s truncated. Max allowed is %d\n", what, max - 1);
}

void
check_snprintf(char *target, int max, const char *string, const char *what)
{
	int retval;

	retval = snprintf(target, max, "%s", string);
	if (retval > max)
		rep_truncate(what, max);
	else if (retval < 0)
		fprintf(stderr, "Output error for %s\n", what);
}

void
init_data_struct(lrc_t *data)
{
	memset(data, 0, sizeof(lrc_t));
	if (!(data->host = calloc(ONE, DOMAIN)))
		rep_error("host in data");
	if (!(data->domain = calloc(ONE, DOMAIN)))
		rep_error("domain in data");
	if (!(data->user = calloc(ONE, NAME)))
		rep_error("name in data");
	if (!(data->db = calloc(ONE, DB)))
		rep_error("db in data");
	if (!(data->ca = calloc(ONE, DOMAIN)))
		rep_error("ca in data");
}

void
clean_data_strcut(lrc_t *data)
{
	if (data) {
		if (data->host)
			free(data->host);
		if (data->domain)
			free(data->domain);
		if (data->user)
			free(data->user);
		if (data->db)
			free(data->db);
		if (data->ca)
			free(data->ca);
		free(data);
	}
}

int
parse_command_line(int argc, char *argv[], lrc_t *data)
{
	int retval = NONE, opt = NONE;

	if (!(data))
		return NODATA;
	while ((opt = getopt(argc, argv, "b:c:d:h:u:ts")) != -1) {
		if (opt == 'b')
			check_snprintf(data->db, DB, optarg, "data->db");
		else if (opt == 'c')
			check_snprintf(data->ca, DOMAIN, optarg, "data->ca");
		else if (opt == 'd')
			check_snprintf(data->domain, DOMAIN, optarg, "data->domain");
		else if (opt == 'h')
			check_snprintf(data->host, DOMAIN, optarg, "data->host");
		else if (opt == 'u')
			check_snprintf(data->user, DOMAIN, optarg, "data->user");
		else if (opt == 't')
			data->tls = 1;
		else if (opt == 's')
			data->ssl = 1;
		else {
			rep_usage(argv[0]);
			return WARG;
		}
	}
	if ((strlen(data->db) == 0) || (strlen(data->domain) == 0) ||
	 (strlen(data->host) == 0) || (strlen(data->user) == 0)) {
		rep_usage(argv[0]);
		return WARG;
	}
	if (((data->tls > 0) || (data->ssl > 0)) && (strlen(data->ca) == 0))
		fprintf(stderr, "No certificate provided. Adding tls_reqcert=never");
	return retval;
}

int
main (int argc, char *argv[])
{
	int retval = NONE;
	lrc_t *data = '\0';
	if (!(data = malloc(sizeof(lrc_t))))
		rep_error("data");
	init_data_struct(data);
	retval = parse_command_line(argc, argv, data);
	clean_data_strcut(data);
	return retval;
}