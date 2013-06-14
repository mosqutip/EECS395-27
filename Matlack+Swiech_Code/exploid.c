#define UEVENT_MSG_LEN 4

/* EXAMPLE CODE BOILERPLATE */
struct uevent {
    int a_thing;
};

int recv(int f, int m, int len, int size) {
    return 3;
}

int fd;
int msg;
int n;

/****************************/

int main(int argc, char const* argv[])
{
    while((n = recv(fd, msg, UEVENT_MSG_LEN, 0)) > 0) {
        struct uevent uevent;
        if(n == UEVENT_MSG_LEN)   /* overflow -- discard */
            continue;
    }
    
    return 0;
}
