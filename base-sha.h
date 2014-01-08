#ifndef HAVE_BASE_H
# define HAVE_BASE_H
# include <glib.h>

enum {
	NONE = 0,
	ONE = 1,
	DECIMAL = 10,
	SURNAMEL = 31,
	SURNAME= 32,
	USERL = 127,
	USER = 128,
	DOMAIN = 256,
	MEM = 300,
	BUFF = 512
};

typedef struct inp_data_s {
	unsigned short int gr, lu, user, np;
	char *dom, *sur, *name, *uname, *pass, *fname;
} inp_data_s;

#ifndef MALLOC_DATA_MEMBER
# define MALLOC_DATA_MEMBER(mem, SIZE) {                            \
	if (!(data->mem = calloc(ONE, SIZE)))                       \
		rep_err("Cannot malloc mem");                       \
}
#endif /* MALLOC_DATA_MEMBER */

#ifndef CLEAN_DATA_MEMBER
# define CLEAN_DATA_MEMBER(mem) {                                   \
	if (data->mem) {                                            \
		free(data->mem);                                    \
	} else {                                                    \
		fprintf(stderr, "data->mem does not exist??\n");    \
		exit (MEM);                                         \
	}                                                           \
}
#endif /* CLEAN_DATA_MEMBER */

#ifndef GET_OPT_ARG
# define GET_OPT_ARG(member, LEN, Name) {                                     \
	if ((slen = snprintf(data->member, LEN, "%s", optarg)) > LEN) {       \
		fprintf(stderr, "Name truncated by %d\n", (slen - LEN) + 1);  \
	}                                                                     \
}
#endif /* GET_OPT_ARG */

#define PASS_SIZE 100

char *
getPassword(const char *message);

void
rep_err(const char *error);

int
init_input_data(inp_data_s *data);

void
clean_data(inp_data_s *data);

void
split_name(inp_data_s *data);

int
parse_command_line(int argc, char *argv[], inp_data_s *data);

void
comm_line_err(char *prog);

void
output_ldif(inp_data_s *data);

char *
get_ldif_domain(char *domain);

char *
get_ldif_user(inp_data_s *data);

char *
get_ldif_pass_hash(char *pass);

int
hex_conv(const char *pass, guchar *out);

#endif /* HAVE_BASE_H */
