#include "analysis.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define MSBFILTER 0x80
#define NBITS 8
#define DIFF 48

double chi_square_analysis(char* bytestream, int size, int nmemb) {
    unsigned char* bits = (unsigned char*)malloc(sizeof(unsigned char) * size * nmemb);
    for (size_t i = 0, index = 0; i < size * nmemb; ++i) {
        if (i % NBITS == 0) {
            index++;
        }
        // Get Most Significant Bit (MSB).
        *(bits + i) = ((*(bytestream + index) & MSBFILTER) >> (NBITS - 1)) + DIFF;
        // Remove MSB.
        *(bytestream + index) <<= 1;
    }

    unsigned long long* nums = (unsigned long long*)malloc(sizeof(unsigned long long) * nmemb);

    // Convert bit strings to integers.
    unsigned char* temp = (unsigned char*)malloc(sizeof(unsigned char) * (size + 1));
    char* end;
    for (size_t i = 0; i < nmemb; ++i) {
        strncpy(temp, bits + (i * size), size);
        *(temp + size) = 0;
        *(nums + i) = (unsigned long long)strtol(temp, &end, 2);
    }

    size_t M = (size_t)pow(2, ceil(log2(size)));
    double P = pow(2, size) / (double)M;
    double E = (double)nmemb / (double)M;
    size_t* O = (size_t*)malloc(sizeof(size_t) * M);

    for (size_t i = 0; i < M; ++i) {
        *(O + i) = 0;
    }

    // Classification
    for (size_t i = 0; i < nmemb; ++i) {
        double temp = (double)*(nums + i);
        for (size_t j = 0; j < M; ++j) {
            if (P * j <= temp && temp < P * (j + 1)) {
                *(O + j) += 1;
                break;
            }
        }
    }

    // Chi-square test
    double chi = 0.0;
    for (size_t i = 0; i < M; ++i) {
        chi += (pow((double)*(O + i) - E, 2) / E);
    }

    free(nums);
    free(O);
    free(bits);
    free(temp);

    return chi;
}

double mean(double* data, int start, int end) {
    double sum = 0.0;
    for (int i = start; i <= end; i++) {
        sum += data[i];
    }

    return sum / (double)(end - start + 1);
}

double stddev(double* data, int start, int end) {
    double avg = mean(data, start, end);
    double std = 0.0;
    for (int i = start; i <= end; i++) {
        std += pow(data[i] - avg, 2);
    }
    return sqrt(std / (double)(end - start + 1));
}

double calculate_RS(double* data, int start, int end) {
    int n = end - start + 1;
    double* Y = (double*)malloc((end - start + 1) * sizeof(double));
    double* Z = (double*)malloc((end - start + 1) * sizeof(double));
    double R, S;

    double M = mean(data, start, end);

    for (int i = 0; i < n; i++) {
        Y[i] = data[start + i] - M;
    }

    Z[0] = Y[0];
    for (int i = 1; i < n; i++) {
        Z[i] = Z[i - 1] + Y[i];
    }

    double min_Z = Z[0], max_Z = Z[0];
    for (int i = 1; i < n; i++) {
        if (Z[i] < min_Z) min_Z = Z[i];
        if (Z[i] > max_Z) max_Z = Z[i];
    }
    R = max_Z - min_Z;

    S = stddev(data, start, end);

    free(Y);
    free(Z);

    return R / S;
}

double Slope(double* logN, double* logRS, int numPoints) {
    double sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
    for (int i = 0; i < numPoints; i++) {
        sumX += logN[i];
        sumY += logRS[i];
        sumXY += logN[i] * logRS[i];
        sumXX += logN[i] * logN[i];
    }
    return (numPoints * sumXY - sumX * sumY) / (numPoints * sumXX - sumX * sumX);
}

double rescaled_range_analysis(char* bytestream, int size, int nmemb) {
    unsigned char* bits = (unsigned char*)malloc(sizeof(unsigned char) * size * nmemb);
    for (size_t i = 0, index = 0; i < size * nmemb; ++i) {
        if (i % NBITS == 0) {
            index++;
        }
        // Get Most Significant Bit (MSB).
        *(bits + i) = ((*(bytestream + index) & MSBFILTER) >> (NBITS - 1)) + DIFF;
        // Remove MSB.
        *(bytestream + index) <<= 1;
    }

    double* data = (double*)malloc(nmemb * sizeof(double));

    // Convert bit strings to integers.
    unsigned char* temp = (unsigned char*)malloc(sizeof(unsigned char) * (size + 1));
    char* end;
    for (size_t i = 0; i < nmemb; ++i) {
        strncpy(temp, bits + (i * size), size);
        *(temp + size) = 0;
        *(data + i) = (double)strtol(temp, &end, 2);
    }

    int windowCtg = log2(nmemb) - 1;
    double* logRS = (double*)malloc(windowCtg * sizeof(double));
    double* logN = (double*)malloc(windowCtg * sizeof(double));

    for (int i = 0, window_num = 1; i < windowCtg; i++, window_num *= 2) {
        double sum_RS = 0.0;
        int window_size = nmemb / window_num;

        for (int j = 0; j < window_num; j++) {
            int start = j * window_size;
            int end = start + window_size - 1;
            double RS = calculate_RS(data, start, end);
            sum_RS += RS;
        }

        double average_RS = sum_RS / window_num;
        logRS[i] = log(average_RS);
        logN[i] = log(window_size);
    }

    return Slope(logN, logRS, windowCtg);
}
