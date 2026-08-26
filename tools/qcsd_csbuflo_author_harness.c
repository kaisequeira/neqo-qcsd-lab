/*
 * Clean-room executable adapter for the pinned CS-BuFLO reference object.
 *
 * This file contains no CS-BuFLO implementation.  The isolated reference
 * image compiles the author's unmodified misc.c and ephemeral exact source
 * slices from the hash-pinned packet/client/server loops.  It links those
 * objects with this adapter.  The otherwise unrelated OpenSSH references in
 * misc.o are satisfied by inert stubs; none are reached by these deterministic
 * vectors.  Extracted source is never installed in a collection image.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void insert_time(unsigned long long time);
void update_tau_interval(unsigned long long start, unsigned long long end,
                         long real_bytes, int is_client);
long update_tau_median(long tau, long *boundary, long total_sent_bytes);
unsigned long long get_current_time_usecs(void);
int channel_idle(unsigned long long *now_usecs, int buffered_bytes,
                 int consumed_bytes, unsigned long long *idle_start);
void set_onload_flag(void);
void unset_onload_flag(void);
void set_paddingdone_flag(void);
void unset_paddingdone_flag(void);
int get_paddingdone_flag(void);
void set_stmode(int mode);

unsigned long long qcsd_author_update_time(unsigned long long now, long tau);
long qcsd_author_client_payload_target(long total_sent_bytes,
                                        long real_incoming_bytes,
                                        int output_buffer_bytes);
long qcsd_author_server_payload_target(long total_sent_bytes,
                                        long real_incoming_bytes,
                                        int output_buffer_bytes);
long qcsd_author_client_total_target(long total_sent_bytes);
long qcsd_author_server_total_target(long total_sent_bytes);
int qcsd_author_early_transition(int transcript_end, long queued_bytes,
                                 int onload, unsigned long long idle_start,
                                 unsigned long long now_usecs,
                                 int output_buffer_bytes,
                                 unsigned long long *result_idle_start);
int qcsd_author_client_transition(int output_buffer_bytes,
                                  long target_sent_bytes,
                                  long total_sent_bytes);
int qcsd_author_server_transition(int output_buffer_bytes,
                                  long target_sent_bytes,
                                  long total_sent_bytes,
                                  int *padding_done);

static uint32_t deterministic_arc4random_value;

uint32_t arc4random(void)
{
    return deterministic_arc4random_value;
}

static long estimator(long first, long second, long end)
{
    long boundary = 16384;

    insert_time((unsigned long long)first);
    insert_time((unsigned long long)second);
    update_tau_interval(0, (unsigned long long)end, 1, 1);
    return update_tau_median(8192, &boundary, boundary);
}

int main(void)
{
    long empty_boundary = 16384;
    long before_boundary = 16384;
    unsigned long long now = get_current_time_usecs();
    unsigned long long idle_start = now;
    const long empty = update_tau_median(8192, &empty_boundary, empty_boundary);
    const long retained = update_tau_median(8192, &before_boundary, 16383);
    const long upper_median = estimator(0, 5000, 15000);
    const long clamped = estimator(0, 1000, 51000);
    int quiet_before;
    int quiet_after;
    int onload_idle;
    int buffered_resets_idle;
    unsigned long long jitter_raw_0;
    unsigned long long jitter_raw_1;
    unsigned long long jitter_raw_100;
    unsigned long long jitter_raw_200;
    unsigned long long jitter_raw_201;
    unsigned long long jitter_stmode_fixed;
    int padding_done_initial;
    int padding_done_after_set;
    int padding_done_after_unset;
    int server_complete_padding_done;
    int server_buffered_padding_done;
    int client_complete_mode;
    int client_exact_tolerance_mode;
    int client_buffered_mode;
    int server_complete_mode;
    int server_buffered_mode;
    int client_early_no_transcript_mode;
    int client_early_queued_write_mode;
    int client_early_onload_mode;
    int client_early_idle_start_mode;
    int client_early_buffered_mode;
    int client_early_quiet_before_mode;
    int client_early_quiet_boundary_mode;
    int server_early_onload_mode;
    int server_early_buffered_mode;
    int server_early_quiet_boundary_mode;
    unsigned long long client_early_idle_start;
    unsigned long long ignored_idle_start;

    set_stmode(0);
    deterministic_arc4random_value = 0;
    jitter_raw_0 = qcsd_author_update_time(1000, 8192) - 1000;
    deterministic_arc4random_value = 1;
    jitter_raw_1 = qcsd_author_update_time(1000, 8192) - 1000;
    deterministic_arc4random_value = 100;
    jitter_raw_100 = qcsd_author_update_time(1000, 8192) - 1000;
    deterministic_arc4random_value = 200;
    jitter_raw_200 = qcsd_author_update_time(1000, 8192) - 1000;
    deterministic_arc4random_value = 201;
    jitter_raw_201 = qcsd_author_update_time(1000, 8192) - 1000;
    set_stmode(1);
    deterministic_arc4random_value = 200;
    jitter_stmode_fixed = qcsd_author_update_time(1000, 8192) - 1000;

    unset_onload_flag();
    quiet_before = channel_idle(&now, 0, 0, &idle_start);
    now = get_current_time_usecs();
    idle_start = now - 2000001;
    quiet_after = channel_idle(&now, 0, 0, &idle_start);
    now = get_current_time_usecs();
    idle_start = now;
    set_onload_flag();
    onload_idle = channel_idle(&now, 0, 0, &idle_start);
    unset_onload_flag();
    now = get_current_time_usecs();
    idle_start = now - 2000001;
    buffered_resets_idle = channel_idle(&now, 32, 0, &idle_start);

    unset_paddingdone_flag();
    padding_done_initial = get_paddingdone_flag();
    set_paddingdone_flag();
    padding_done_after_set = get_paddingdone_flag();
    unset_paddingdone_flag();
    padding_done_after_unset = get_paddingdone_flag();

    client_early_no_transcript_mode = qcsd_author_early_transition(
        0, 0, 0, 1, 2000001, 0, &ignored_idle_start);
    client_early_queued_write_mode = qcsd_author_early_transition(
        1, 1, 1, 1, 2000001, 0, &ignored_idle_start);
    client_early_onload_mode = qcsd_author_early_transition(
        1, 0, 1, 1, 2000001, 0, &ignored_idle_start);
    client_early_idle_start_mode = qcsd_author_early_transition(
        1, 0, 0, 0, 5000000, 0, &client_early_idle_start);
    client_early_buffered_mode = qcsd_author_early_transition(
        1, 0, 0, 1000000, 2999999, 1, &ignored_idle_start);
    client_early_quiet_before_mode = qcsd_author_early_transition(
        1, 0, 0, 1000000, 2999999, 0, &ignored_idle_start);
    client_early_quiet_boundary_mode = qcsd_author_early_transition(
        1, 0, 0, 1000000, 3000000, 0, &ignored_idle_start);
    server_early_onload_mode = qcsd_author_early_transition(
        1, 0, 1, 1, 2000001, 0, &ignored_idle_start);
    server_early_buffered_mode = qcsd_author_early_transition(
        1, 0, 0, 1000000, 2999999, 1, &ignored_idle_start);
    server_early_quiet_boundary_mode = qcsd_author_early_transition(
        1, 0, 0, 1000000, 3000000, 0, &ignored_idle_start);

    client_complete_mode = qcsd_author_client_transition(0, 3072, 2525);
    client_exact_tolerance_mode = qcsd_author_client_transition(0, 3072, 2524);
    client_buffered_mode = qcsd_author_client_transition(1, 3072, 2525);
    server_complete_mode = qcsd_author_server_transition(
        32, 3072, 2525, &server_complete_padding_done);
    server_buffered_mode = qcsd_author_server_transition(
        33, 3072, 2525, &server_buffered_padding_done);

    if (printf(
            "{\"estimator\":{\"clamped\":%ld,\"empty\":%ld,"
            "\"empty_next_boundary\":%ld,\"pre_boundary\":%ld,"
            "\"pre_boundary_next_boundary\":%ld,\"upper_median\":%ld},"
            "\"early_termination\":{\"client_buffered_mode\":%d,"
            "\"client_idle_start_mode\":%d,\"client_idle_start_us\":%llu,"
            "\"client_no_transcript_mode\":%d,\"client_onload_mode\":%d,"
            "\"client_queued_write_mode\":%d,\"client_quiet_before_mode\":%d,"
            "\"client_quiet_boundary_mode\":%d,\"server_buffered_mode\":%d,"
            "\"server_onload_mode\":%d,\"server_quiet_boundary_mode\":%d},"
            "\"jitter\":{\"raw_0\":%llu,\"raw_1\":%llu,"
            "\"raw_100\":%llu,\"raw_200\":%llu,"
            "\"raw_201_modulo\":%llu,\"stmode_fixed\":%llu},"
            "\"padding\":{\"client_payload_0_0\":%ld,"
            "\"client_payload_1000_1100\":%ld,"
            "\"client_payload_1000_1048\":%ld,"
            "\"server_payload_1000_1100\":%ld,"
            "\"client_total_0_0\":%ld,"
            "\"client_total_1000_1100\":%ld,"
            "\"client_total_1000_1048\":%ld,"
            "\"server_total_1000_1100\":%ld},"
            "\"padding_done\":{\"after_set\":%d,\"after_unset\":%d,"
            "\"initial\":%d},"
            "\"quiet\":{\"buffered_resets_idle\":%d,\"onload_idle\":%d,"
            "\"quiet_after\":%d,\"quiet_before\":%d},"
            "\"termination\":{\"client_buffered_mode\":%d,"
            "\"client_complete_mode\":%d,"
            "\"client_exact_tolerance_mode\":%d,"
            "\"server_buffered_mode\":%d,"
            "\"server_buffered_padding_done\":%d,"
            "\"server_complete_mode\":%d,"
            "\"server_complete_padding_done\":%d}}\n",
            clamped, empty, empty_boundary, retained, before_boundary,
            upper_median, client_early_buffered_mode,
            client_early_idle_start_mode, client_early_idle_start,
            client_early_no_transcript_mode, client_early_onload_mode,
            client_early_queued_write_mode, client_early_quiet_before_mode,
            client_early_quiet_boundary_mode, server_early_buffered_mode,
            server_early_onload_mode, server_early_quiet_boundary_mode,
            jitter_raw_0, jitter_raw_1, jitter_raw_100,
            jitter_raw_200, jitter_raw_201, jitter_stmode_fixed,
            qcsd_author_client_payload_target(0, 0, 0),
            qcsd_author_client_payload_target(2100, 1000, 0),
            qcsd_author_client_payload_target(2048, 1000, 0),
            qcsd_author_server_payload_target(2100, 1000, 0),
            qcsd_author_client_total_target(0),
            qcsd_author_client_total_target(2100),
            qcsd_author_client_total_target(2048),
            qcsd_author_server_total_target(2100),
            padding_done_after_set, padding_done_after_unset,
            padding_done_initial, buffered_resets_idle, onload_idle,
            quiet_after, quiet_before, client_buffered_mode,
            client_complete_mode, client_exact_tolerance_mode,
            server_buffered_mode, server_buffered_padding_done,
            server_complete_mode, server_complete_padding_done) < 0) {
        return 1;
    }
    return 0;
}

/* Unreached dependencies retained in the monolithic historical misc.o. */
uintptr_t __stack_chk_guard;

void change_to_relative_time(void) {}
void debug(const char *format, ...) { (void)format; }
void debug2(const char *format, ...) { (void)format; }
void debug3(const char *format, ...) { (void)format; }
void error(const char *format, ...) { (void)format; }
void fatal(const char *format, ...) { (void)format; abort(); }
void *hm_build(void) { return NULL; }
void *hm_lookup(void) { return NULL; }
void *load_st(void) { return NULL; }
void *split(void) { return NULL; }
int sys_tun_open(void) { return -1; }
void *xcalloc(size_t count, size_t size) { return calloc(count, size); }
void xfree(void *value) { free(value); }
void *xrealloc(void *value, size_t size) { return realloc(value, size); }
char *xstrdup(const char *value) { (void)value; return NULL; }
size_t strlcat(char *destination, const char *source, size_t size)
{
    (void)destination;
    (void)source;
    (void)size;
    return 0;
}
size_t strlcpy(char *destination, const char *source, size_t size)
{
    (void)destination;
    (void)source;
    (void)size;
    return 0;
}
long long strtonum(const char *value, long long minimum, long long maximum,
                   const char **error_string)
{
    (void)value;
    (void)minimum;
    (void)maximum;
    (void)error_string;
    return 0;
}
