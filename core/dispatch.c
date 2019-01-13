#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...);
extern int DisplayInfo(const char *fmtstring, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmtstring, ...);

extern int NumberOfRowsFile(const char *path, size_t *num);
extern int ProcessFile(const char *path, pStringHeader *output, int flag, size_t start, size_t end);
extern int FreeProcessFileBuff(pStringHeader p);

int TaskAssignmentForFile(const char *path, pStringHeader *output, int flag, const int process_num, const int thread_num, const int serial_num)
{
    // multi process and thread
    // assign task for each thread
    size_t num;
    if (NumberOfRowsFile(path, &num))
    {
        DisplayError("Count file's rows failed");
        return -1;
    }

    size_t cut = (num) / ((size_t)process_num * (size_t)thread_num);
    size_t start = serial_num * cut;
    size_t end = (serial_num + 1) * cut;

    if (ProcessFile(path, output, flag, start, end))
    {
        DisplayError("Processing file failed");
        return -1;
    }

    return 0;
}