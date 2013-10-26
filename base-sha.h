#ifndef HAVE_BASE_H
# define HAVE_BASE_H

enum {
	NONE = 0,
	ONE = 1,
	DECIMAL = 10,
	SURNAME= 31,
	USER = 32,
	DOMAIN = 256,
	MEM = 300
};

typedef struct inp_data_s {
	unsigned short int gr, lu, user;
	char *dom, *pass, *sur, *name;
} inp_data_s;

void
rep_err(const char *error);

int
init_input_data(inp_data_s *data);

void
clean_data(inp_data_s *data);

int
parse_command_line(int argc, char *argv[], inp_data_s *data);

#endif /* HAVE_BASE_H */
