#pragma once

#include <sys/cdefs.h>
#define EVENT_TYPE_DDWAF_RUN ((unsigned char)1)
#define EVENT_TYPE_MATCH_RULE ((unsigned char)2)

struct event {
    int tid;
    unsigned char type;
};

struct event_ddwaf_run {
    struct event event;
    unsigned long duration;
};

struct event_match_rule {
    struct event event;
    unsigned long duration;
    char rule_id[22];
    unsigned short rule_id_len;
};
