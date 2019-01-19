#include <stdio.h>
#include <pthread.h>

void call(void)
{
    pthread_t self = pthread_self();
    printf("ld")
}

int main(void)
{
    pthread_t tid;

}