#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int result;
    uid_t uid_to_set;

    if(argc != 2){
        printf("Bad argument\n");
        printf("a.out <uid_t to set>\n");
        return 1;
    }
    result = atoi(*(argv+1));
    uid_to_set = (uid_t) result;

    printf("Real user id: %d\n", getuid());
    printf("Effective user id: %d\n", geteuid());

    printf("Settings uid to %d\n", uid_to_set);
    result = setuid(uid_to_set);

    printf("Result: %d\n", result);

    if(result == 0){
        printf("Success!\n");
        printf("Real user id: %d\n", getuid());
        printf("Effective user id: %d\n", geteuid());
    } else {
        printf("failed!\n");
    }
    return 0;
}
