#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmt, ...);

extern int GetFileLines(const char *path, size_t *num);
extern int ProcessFile(const char *path, pStringHeader *output, int flag, size_t start, size_t end);

int TaskAssignmentForFile(const char *path, pStringHeader *output, int flag, const int max_process, const int max_thread, const int serial_num)
{
    // multi process and thread
    // assign task for each thread
    size_t num;
    if (GetFileLines(path, &num))
    {
        DisplayError("Count file's rows failed");
        return -1;
    }

    size_t cut = (num) / ((size_t)max_process * (size_t)max_thread);
    size_t start = serial_num * cut;
    size_t end = (serial_num + 1) * cut;

    if (ProcessFile(path, output, flag, start, end))
    {
        DisplayError("Processing file failed");
        return -1;
    }

    return 0;
}