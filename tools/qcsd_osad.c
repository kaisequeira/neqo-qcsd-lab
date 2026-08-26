#include <math.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#if defined(_WIN32)
#define QCSD_EXPORT __declspec(dllexport)
#else
#define QCSD_EXPORT __attribute__((visibility("default")))
#endif

/*
 * Clean-room restricted optimal-string-alignment distance for the DLSVM
 * evaluation backend.  The operation costs are the CCS'12/Ca-OSAD values:
 * insertion=2, deletion=2, substitution=2, adjacent transposition=0.1.
 * Three rolling rows retain the restricted-OSA recurrence without allocating
 * an O(n*m) matrix.
 */
QCSD_EXPORT double qcsd_osad_distance(
    const int32_t *left,
    size_t left_length,
    const int32_t *right,
    size_t right_length
) {
    const double insertion_cost = 2.0;
    const double deletion_cost = 2.0;
    const double substitution_cost = 2.0;
    const double transposition_cost = 0.1;

    if ((left_length != 0 && left == NULL) || (right_length != 0 && right == NULL)) {
        return NAN;
    }
    if (left_length == 0) {
        return insertion_cost * (double)right_length;
    }
    if (right_length == 0) {
        return deletion_cost * (double)left_length;
    }

    /* Insertion and deletion have equal cost, so swapping only reduces memory. */
    if (right_length > left_length) {
        const int32_t *temporary_values = left;
        left = right;
        right = temporary_values;
        const size_t temporary_length = left_length;
        left_length = right_length;
        right_length = temporary_length;
    }
    if (right_length == SIZE_MAX || right_length + 1 > SIZE_MAX / (3 * sizeof(double))) {
        return NAN;
    }

    const size_t width = right_length + 1;
    double *rows = malloc(3 * width * sizeof(double));
    if (rows == NULL) {
        return NAN;
    }
    double *previous_previous = rows;
    double *previous = rows + width;
    double *current = rows + 2 * width;
    for (size_t column = 0; column < width; ++column) {
        previous[column] = insertion_cost * (double)column;
    }

    for (size_t row = 1; row <= left_length; ++row) {
        current[0] = deletion_cost * (double)row;
        for (size_t column = 1; column <= right_length; ++column) {
            const double substitution =
                left[row - 1] == right[column - 1] ? 0.0 : substitution_cost;
            double value = previous[column] + deletion_cost;
            const double insertion = current[column - 1] + insertion_cost;
            if (insertion < value) {
                value = insertion;
            }
            const double replacement = previous[column - 1] + substitution;
            if (replacement < value) {
                value = replacement;
            }
            if (
                row > 1 && column > 1 &&
                left[row - 1] == right[column - 2] &&
                left[row - 2] == right[column - 1]
            ) {
                const double transposition =
                    previous_previous[column - 2] + transposition_cost;
                if (transposition < value) {
                    value = transposition;
                }
            }
            current[column] = value;
        }
        double *rotated = previous_previous;
        previous_previous = previous;
        previous = current;
        current = rotated;
    }

    const double result = previous[right_length];
    free(rows);
    return result;
}
