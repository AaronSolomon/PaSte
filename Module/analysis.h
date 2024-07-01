// The chi-square function
double chi_square_analysis(char* bytestream, int size, int nmemb);

// The RS analysis function
double rescaled_range_analysis(char* bytestream, int size, int nmemb);

double mean(double* data, int start, int end);

double stddev(double* data, int start, int end);

double calculate_RS(double* data, int start, int end);

double Slope(double* logN, double* logRS, int numPoints);