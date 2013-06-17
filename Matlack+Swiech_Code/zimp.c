#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>

#define PROPERTY_VALUE_MAX 16
#define DEFAULT_ADB_LOCAL_TRANSPORT_PORT 15
#define F_OK 14
#define _LINUX_CAPABILITY_VERSION 1
#define AID_SHELL 1
#define AID_ADB 2
#define AID_GRAPHICS 3
#define AID_INET 4
#define AID_INPUT 5
#define AID_LOG 6
#define AID_MOUNT 7
#define AID_NET_BT 8
#define AID_NET_BT_ADMIN 9
#define AID_SDCARD_RW 10
#define PR_SET_KEEPCAPS 12
#define CAP_SYS_BOOT 13
#define false 0

typedef unsigned short u4;
typedef unsigned int u8;
typedef struct ArrayObject ArrayObject;

struct g {
    int zygote;
};

struct g gDvm;

typedef struct Thread Thread;

struct Thread {
    int systemTid;
};

struct ArrayObject {
    int obj;
    u4 length;
    u8 contents;
};

static void adb_cleanup(void){
    // call to usb_cleanup
    int i = 1;
    return;
}

struct __user_cap_header_struct {
    unsigned int version;
    int pid;
};
struct __user_cap_data_struct {
    unsigned int effective;
    unsigned int permitted;
    unsigned int inheritable;
};

static pid_t forkAndSpecializeCommon(const u4* args)
{
    pid_t pid;

    uid_t uid = (uid_t) args[0];
    gid_t gid = (gid_t) args[1];
    ArrayObject* gids = (ArrayObject *)args[2];
    u4 debugFlags = args[3];
    ArrayObject *rlimits = (ArrayObject *)args[4];

    if (!gDvm.zygote) {
        dvmThrowException("Ljava/lang/IllegalStateException;",
            "VM instance not started with -Xzygote");

        return -1;
    }

    if (!dvmGcPreZygoteFork()) {
        LOGE("pre-fork heap failed\n");
        dvmAbort();
    }

    setSignalHandler();

    dvmDumpLoaderStats("zygote");
    pid = fork();

    if (pid == 0) {
        int err;
        /* The child process */

#ifdef HAVE_ANDROID_OS
        extern int gMallocLeakZygoteChild;
        gMallocLeakZygoteChild = 1;

        /* keep caps across UID change, unless we're staying root */
        if (uid != 0) {
            err = prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

            if (err < 0) {
                LOGW("cannot PR_SET_KEEPCAPS: %s", strerror(errno));
            }
        }

#endif /* HAVE_ANDROID_OS */

        err = setgroupsIntarray(gids);

        if (err < 0) {
            LOGW("cannot setgroups(): %s", strerror(errno));
        }

        err = setrlimitsFromArray(rlimits);

        if (err < 0) {
            LOGW("cannot setrlimit(): %s", strerror(errno));
        }

        err = setgid(gid);
        if (err < 0) {
            /*LOGW("cannot setgid(%d): %s", gid, strerror(errno));*/
            LOGW("cannot setgid(): %s", strerror(errno));
        }

        err = setuid(uid);
        if (err < 0) {
            /*LOGW("cannot setuid(%d): %s", uid, strerror(errno));*/
            LOGW("cannot setuid(): %s", strerror(errno));
        }

        /*
         * Our system thread ID has changed.  Get the new one.
         */
        Thread* thread = dvmThreadSelf();
        thread->systemTid = dvmGetSysThreadId();

        /* configure additional debug options */
        enableDebugFeatures(debugFlags);

        unsetSignalHandler();
        gDvm.zygote = false;
        if (!dvmInitAfterZygote()) {
            LOGE("error in post-zygote initialization\n");
            dvmAbort();
        }
    } else if (pid > 0) {
        /* the parent process */
    }

    return pid;
}

int main(int argc, char const* argv[])
{
    const u4* a = (u4*)argv;
    pid_t p;
    p = forkAndSpecializeCommon(a);
    return 0;
}

