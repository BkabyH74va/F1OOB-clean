// iokit_enum_safe.mm
// Target: iOS 27.0.1
// Bug class: CWE-862 Missing Authorization
// Strategy: Safely enumerate IOKit services with NULL checks

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#define LOG_FILE "/var/mobile/Media/Downloads/iokit_enum_log.txt"

FILE *g_log = NULL;
int g_openable_count = 0;
int g_blocked_count = 0;
int g_total_count = 0;
int g_notfound_count = 0;

void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);
    fflush(g_log);
}

// Safe service test with NULL checks
int test_service(const char *name) {
    kern_return_t kr;
    io_service_t service = 0;
    io_connect_t connect = 0;
    
    // Get matching service
    CFMutableDictionaryRef matching = IOServiceMatching(name);
    if (!matching) {
        return -1; // Matching dictionary failed
    }
    
    service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (!service) {
        CFRelease(matching);
        return -2; // Service not found
    }
    
    // Try to open
    kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    IOObjectRelease(service);
    
    if (kr == KERN_SUCCESS) {
        IOServiceClose(connect);
        return 1; // Openable
    } else if (kr == kIOReturnNotPermitted) {
        return 0; // Blocked by sandbox
    } else {
        return -3; // Other error
    }
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        g_log = fopen(LOG_FILE, "w");
        if (!g_log) g_log = stdout;
        
        log_msg("=== IOKit Safe Enumeration Started ===\n");
        log_msg("PID: %d\n", getpid());
        log_msg("Looking for CWE-862 candidates\n\n");
        
        // Test list
        const char *services[] = {
            "AppleAPFSUserClient",
            "AppleNVMeSMARTUserClient",
            "IOHIDLibUserClient",
            "IOAESAcceleratorUserClient",
            "IOBlockStorageDevice",
            "IOMedia",
            "IOMediaBSDClient",
            "IOUSBDevice",
            "IOUSBHostDevice",
            "IOBluetoothDevice",
            "IOAudioDevice",
            "IOGraphicsDevice",
            "IONetworkInterface",
            "IONetworkController",
            "IOPlatformDevice",
            "IOPlatformExpert",
            "IOCPU",
            "IOPowerDevice",
            "IOService",
            "IORegistryEntry",
            NULL
        };
        
        log_msg("%-40s | %-12s\n", "SERVICE", "STATUS");
        log_msg("------------------------------------------------\n");
        
        for (int i = 0; services[i] != NULL; i++) {
            g_total_count++;
            int result = test_service(services[i]);
            
            if (result == 1) {
                g_openable_count++;
                log_msg("%-40s | [+] OPEN\n", services[i]);
            } else if (result == 0) {
                g_blocked_count++;
                log_msg("%-40s | [-] BLOCKED\n", services[i]);
            } else if (result == -2) {
                g_notfound_count++;
                log_msg("%-40s | [?] NOT FOUND\n", services[i]);
            } else {
                log_msg("%-40s | [?] ERROR %d\n", services[i], result);
            }
            
            usleep(10000); // 10ms delay
        }
        
        log_msg("\n=== Summary ===\n");
        log_msg("Total: %d\n", g_total_count);
        log_msg("Openable: %d\n", g_openable_count);
        log_msg("Blocked: %d\n", g_blocked_count);
        log_msg("Not found: %d\n", g_notfound_count);
        
        fclose(g_log);
    }
    return 0;
}
