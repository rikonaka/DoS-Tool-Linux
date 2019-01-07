#define DEBUG_OFF 0
#define DEBUG_LEVEL_1 1 // show the importance value
#define DEBUG_LEVEL_2 2 // show the not importance value
#define DEBUG_LEVEL_3 3 // show function start, end

#define MAX_LOG_BUF_SIZE 50

int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...);
int DisplayInfo(const char *fmtstring, ...);
int DisplayWarning(const char *fmtsring, ...);
int DisplayError(const char *fmtstring, ...);