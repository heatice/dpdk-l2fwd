#include <stdlib.h>
#include <getopt.h>

#include "hanr_client.h"
#include "hanr_parse_cmds.h"

static struct option long_opts[] = {
    {"msgtype", required_argument, 0, 't'},
    {"count", required_argument, 0, 'c'},
    {"rate", required_argument, 0, 'r'},
    {"mode", required_argument, 0, 'm'},
    {"verbose", no_argument, NULL, 'v'},

};

#define HANR_CLIENT_OPTIONS_TYPE "\tType of IRS Message: "  \
                               "\t1 - Register Request; " \
                               "\t2 - Withdraw Request; " \
                               "\t3 - Query Request;"      
#define HANR_CLIENT_OPTIONS_COUNT "\tCount - Total packets count to Send"
#define HANR_CLIENT_OPTIONS_RATE  "\tRate - Packets per second to Send"
#define HANR_CLIENT_OPTIONS_VERBOSE "\tVerbose - Verbose"
#define HANR_CLIENT_OPTIONS_MODE "\tMode of HANR Plugins: "\
                                "\t0 - T0 Plugins; " \
                                "\t1 - T1 Plugins; " \
                                "\t2 - T2 Plugins; " \

static void hanr_client_usage()
{
    printf("\nUsage: hanr_client [EAL options] -- -t msgtype\n");
    printf("\t---%s(-%c)%s\n", long_opts[0].name, (char)long_opts[0].val, HANR_CLIENT_OPTIONS_TYPE);
    printf("\t---%s(-%c)%s\n", long_opts[1].name, (char)long_opts[1].val, HANR_CLIENT_OPTIONS_COUNT);
    printf("\t---%s(-%c)%s\n", long_opts[2].name, (char)long_opts[2].val, HANR_CLIENT_OPTIONS_RATE);
    printf("\t---%s(-%c)%s\n", long_opts[3].name, (char)long_opts[3].val, HANR_CLIENT_OPTIONS_MODE);
    printf("\t---%s(-%c)%s\n", long_opts[4].name, (char)long_opts[4].val, HANR_CLIENT_OPTIONS_VERBOSE);
}

/**
 * @brief parse command line options
 * @param  opts             My Param doc
 * @param  argc             My Param doc
 * @param  argv             My Param doc
 * @return int 
 */
int hanr_client_parse_cmds(struct hanr_client_conf *opts, int argc, char *argv[])
{
    int ret = 0;
    int idx = 0;
    int opt;
    char short_opts[] = "t:c:r:m:v";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &idx)) != -1)
    {
        switch (opt)
        {
        case 't':
            opts->msgtype = atoi(optarg);
            break;
        case 'v':
            opts->verbose = 1;
            break;
        case 'c':
            opts->count = atoi(optarg);
            break;
        case 'm':
            opts->mode = atoi(optarg);
            printf("Running mode of HANR:%d\n",opts->mode);
            break;
        case 'r':
            opts->rate = atoi(optarg);
            break;
        default:
            hanr_client_usage();
            return -1;
        }
    }

    if (opts->msgtype >= HANR_MSG_MAX)
    {
        hanr_client_usage();
        return -1;
    }

    return 0;
}