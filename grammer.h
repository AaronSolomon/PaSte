void inject_file(char* infile, char* outfile, char* hiddenfile, char* keyfile,
                 int protocol, int start, int size);
void select_file(char* infile, char* outfile, char* keyfile,
                 int protocol, int start, int size);
void chi_square_analysis_of_file(char* infile, int protocol, int start, int size);
void rescaled_range_analysis_of_file(char* infile, int protocol, int start, int size);
void help(int type);
