#define LOG_OFF 0
#define LOG_INFO 1
#define LOG_DEBUG 2
#define LOG_ERROR 3

#define MAX_LOG_BUF_SIZE 100

int ShowUsage();
int Log(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...);