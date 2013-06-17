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

int main(int argc, char const* argv[])
{
    adb_main(1,8080);
    return 0;
}

int adb_main(int is_daemon, int server_port)
{
#if !ADB_HOST
    int secure = 0;
    int port;
    char value[PROPERTY_VALUE_MAX];
#endif

    atexit(adb_cleanup);
#ifdef HAVE_WIN32_PROC
    SetConsoleCtrlHandler( ctrlc_handler, TRUE );
#elif defined(HAVE_FORKEXEC)
    signal(SIGCHLD, sigchld_handler);
    signal(SIGPIPE, SIG_IGN);
#endif

    init_transport_registration();


#if ADB_HOST
    HOST = 1;
    usb_vendors_init();
    usb_init();
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);

    char local_name[30];
    build_local_name(local_name, sizeof(local_name), server_port);
    if(install_listener(local_name, "*smartsocket*", NULL)) {
        exit(1);
    }
#else
    /* run adbd in secure mode if ro.secure is set and
    ** we are not in the emulator
    */
    property_get("ro.kernel.qemu", value, "");
    if (strcmp(value, "1") != 0) {
        property_get("ro.secure", value, "");
        if (strcmp(value, "1") == 0) {
            // don't run as root if ro.secure is set...
            secure = 1;

            // ... except we allow running as root in userdebug builds if the 
            // service.adb.root property has been set by the "adb root" command
            property_get("ro.debuggable", value, "");
            if (strcmp(value, "1") == 0) {
                property_get("service.adb.root", value, "");
                if (strcmp(value, "1") == 0) {
                    secure = 0;
                }
            }
        }
    }

    /* don't listen on a port (default 5037) if running in secure mode */
    /* don't run as root if we are running in secure mode */
    if (secure) {
        struct __user_cap_header_struct header;
        struct __user_cap_data_struct cap;

        prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

        /* add extra groups:
        ** AID_ADB to access the USB driver
        ** AID_LOG to read system logs (adb logcat)
        ** AID_INPUT to diagnose input issues (getevent)
        ** AID_INET to diagnose network issues (netcfg, ping)
        ** AID_GRAPHICS to access the frame buffer
        ** AID_NET_BT and AID_NET_BT_ADMIN to diagnose bluetooth (hcidump)
        ** AID_SDCARD_RW to allow writing to the SD card
        ** AID_MOUNT to allow unmounting the SD card before rebooting
        */
        gid_t groups[] = { AID_ADB, AID_LOG, AID_INPUT, AID_INET, AID_GRAPHICS,
                           AID_NET_BT, AID_NET_BT_ADMIN, AID_SDCARD_RW, AID_MOUNT };
        setgroups(sizeof(groups)/sizeof(groups[0]), groups);

        /* then switch user and group to "shell" */
        setgid(AID_SHELL);
        setuid(AID_SHELL);

        /* set CAP_SYS_BOOT capability, so "adb reboot" will succeed */
        header.version = _LINUX_CAPABILITY_VERSION;
        header.pid = 0;
        cap.effective = cap.permitted = (1 << CAP_SYS_BOOT);
        cap.inheritable = 0;
        capset(&header, &cap);

        D("Local port disabled\n");
    } else {
        char local_name[30];
        build_local_name(local_name, sizeof(local_name), server_port);
        if(install_listener(local_name, "*smartsocket*", NULL)) {
            exit(1);
        }
    }

        /* for the device, start the usb transport if the
        ** android usb device exists and the "service.adb.tcp.port" and
        ** "persist.adb.tcp.port" properties are not set.
        ** Otherwise start the network transport.
        */
    property_get("service.adb.tcp.port", value, "");
    if (!value[0])
        property_get("persist.adb.tcp.port", value, "");
    if (sscanf(value, "%d", &port) == 1 && port > 0) {
        // listen on TCP port specified by service.adb.tcp.port property
        local_init(port);
    } else if (access("/dev/android_adb", F_OK) == 0) {
        // listen on USB
        usb_init();
    } else {
        // listen on default port
        local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    }
    init_jdwp();
#endif

    if (is_daemon)
    {
        // inform our parent that we are up and running.
#ifdef HAVE_WIN32_PROC
        DWORD  count;
        WriteFile( GetStdHandle( STD_OUTPUT_HANDLE ), "OK\n", 3, &count, NULL );
#elif defined(HAVE_FORKEXEC)
        fprintf(stderr, "OK\n");
#endif
        start_logging();
    }

    fdevent_loop();

    usb_cleanup();

    return 0;
}
