#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "cfg_tokenizer.h"


struct Result {
    enum Token type;
    const char *value;
};

struct Test {
    const char *config;
    struct Result *results;
    int len;
};

static char config1[] = "# Comment\n"
                 "numbers {\n"
                 "   one\n"
                 "   two\n"
                 "   three\n"
                 "   \"[0-9a-z-]+\\.edu\"\n"
                 "}";
static struct Result results1[] = {
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "numbers" },
    { TOKEN_OBRACE, NULL },
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "one" },
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "two" },
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "three" },
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "[0-9a-z-]+.edu" },
    { TOKEN_EOL, NULL },
    { TOKEN_CBRACE, NULL },
    { TOKEN_END, NULL },
};

/* A word may be terminated by the end of the file */
static char config2[] = "pidfile /var/run/sniproxy.pid";
static struct Result results2[] = {
    { TOKEN_WORD, "pidfile" },
    { TOKEN_WORD, "/var/run/sniproxy.pid" },
    { TOKEN_END, NULL },
};

/* But not inside an open quote */
static char config3[] = "pattern \"unterminated";
static struct Result results3[] = {
    { TOKEN_WORD, "pattern" },
    { TOKEN_ERROR, NULL },
};

/* One line blocks */
/* doubled backslash, as documented, to pass \. through to the regex */
static char config4[] = "table { ^example\\\\.com$ 192.0.2.1 }";
static struct Result results4[] = {
    { TOKEN_WORD, "table" },
    { TOKEN_OBRACE, NULL },
    { TOKEN_WORD, "^example\\.com$" },
    { TOKEN_WORD, "192.0.2.1" },
    { TOKEN_CBRACE, NULL },
    { TOKEN_END, NULL },
};

static struct Test tests[] = {
    { config1, results1, sizeof(results1) / sizeof(struct Result) },
    { config2, results2, sizeof(results2) / sizeof(struct Result) },
    { config3, results3, sizeof(results3) / sizeof(struct Result) },
    { config4, results4, sizeof(results4) / sizeof(struct Result) },
    { NULL, NULL, 0 } /* End of tests */
};

int main(void) {
    FILE *cfg;
    char buffer[256];
    enum Token token;
    struct Test *test;
    int i;

    for (test = tests; test->config; test++) {
        /* Fresh file for each test, so a shorter config doesn't leave the
         * tail of a previous one behind */
        cfg = tmpfile();
        if (cfg == NULL) {
            perror("tmpfile");
            return 1;
        }

        fprintf(cfg, "%s", test->config);
        rewind(cfg);

        for (i = 0; i < test->len; i++) {
            token = next_token(cfg, buffer, sizeof(buffer));
            assert(token == test->results[i].type);
            if (test->results[i].value)
                assert(strncmp(buffer, test->results[i].value, sizeof(buffer)) == 0);
        }

        fclose(cfg);
    }

    return (0);
}
