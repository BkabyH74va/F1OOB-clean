// iokit_enum_fast.mm
// Target: iOS 27.0.1
// Bug class: CWE-862 Missing Authorization
// Strategy: Enumerate all IOKit services, log which ones open WITHOUT sandbox blocking

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

void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);
    fflush(g_log);
}

// Quick test: can we open this service?
int test_service(const char *name) {
    kern_return_t kr;
    io_service_t service;
    io_connect_t connect;
    
    // Get service by name
    service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(name));
    if (!service) return -1; // Not found
    
    // Try to open
    kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    IOObjectRelease(service);
    
    if (kr == KERN_SUCCESS) {
        IOServiceClose(connect);
        return 1; // Openable
    } else if (kr == kIOReturnNotPermitted) {
        return 0; // Blocked by sandbox/MACF
    } else if (kr == kIOReturnUnsupported) {
        return -2; // Service doesn't support user clients
    } else if (kr == kIOReturnNoMemory) {
        return -3; // Out of memory
    } else if (kr == kIOReturnNoResources) {
        return -4; // No resources
    } else if (kr == kIOReturnExclusiveAccess) {
        return -5; // Exclusive access required
    } else if (kr == kIOReturnBadArgument) {
        return -6; // Bad argument
    } else if (kr == kIOReturnNotFound) {
        return -7; // Not found
    } else if (kr == kIOReturnNotReady) {
        return -8; // Not ready
    } else if (kr == kIOReturnOffline) {
        return -9; // Offline
    } else if (kr == kIOReturnNotAttached) {
        return -10; // Not attached
    } else if (kr == kIOReturnBusy) {
        return -11; // Busy
    } else if (kr == kIOReturnTimeout) {
        return -12; // Timeout
    } else if (kr == kIOReturnAborted) {
        return -13; // Aborted
    } else if (kr == kIOReturnInvalid) {
        return -14; // Invalid
    } else if (kr == kIOReturnError) {
        return -15; // General error
    } else {
        return -100; // Unknown error
    }
}

const char* get_error_string(int code) {
    switch (code) {
        case -1: return "NOT FOUND";
        case -2: return "NO USER CLIENT";
        case -3: return "NO MEMORY";
        case -4: return "NO RESOURCES";
        case -5: return "EXCLUSIVE ACCESS";
        case -6: return "BAD ARGUMENT";
        case -7: return "NOT FOUND";
        case -8: return "NOT READY";
        case -9: return "OFFLINE";
        case -10: return "NOT ATTACHED";
        case -11: return "BUSY";
        case -12: return "TIMEOUT";
        case -13: return "ABORTED";
        case -14: return "INVALID";
        case -15: return "GENERAL ERROR";
        case -100: return "UNKNOWN ERROR";
        default: return "???";
    }
}

int main(int argc, char *argv[]) {
    g_log = fopen(LOG_FILE, "w");
    if (!g_log) g_log = stdout;
    
    log_msg("=== IOKit Service Enumeration Started ===\n");
    log_msg("Looking for CWE-862 candidates (openable without entitlement)\n\n");
    
    // Common IOKit services to test (known + suspected)
    const char *services[] = {
        // Storage/FS (APFS blocked, try others)
        "AppleAPFSUserClient",
        "AppleAPFSContainerBSDClient",
        "AppleAPFSVolumeBSDClient",
        "AppleAPFSSnapshotBSDClient",
        "AppleAPFSKeybagUserClient",
        "AppleAPFSEncryptedBSDClient",
        "AppleAPFSHealthDeviceBSDClient",
        "AppleAPFSTreeBSDClient",
        "AppleAPFSMaintenanceDeviceBSDClient",
        "AppleAPFSSpaceManagerBSDClient",
        "AppleAPFSEncryptedDeviceBSDClient",
        "AppleAPFSMediaBSDClient",
        "AppleAPFSFusionDeviceBSDClient",
        "AppleAPFSMediaUserClient",
        "AppleAPFSContainerUserClient",
        "AppleAPFSVolumeUserClient",
        "AppleAPFSSnapshotUserClient",
        "AppleAPFSKeybagUserClient",
        "AppleAPFSEncryptedUserClient",
        "AppleAPFSHealthDeviceUserClient",
        "AppleAPFSTreeUserClient",
        "AppleAPFSMaintenanceDeviceUserClient",
        "AppleAPFSSpaceManagerUserClient",
        "AppleAPFSEncryptedDeviceUserClient",
        "AppleAPFSMediaUserClient",
        "AppleAPFSFusionDeviceUserClient",
        
        // Generic I/O
        "IOBlockStorageDevice",
        "IOBlockStorageDriver",
        "IOMedia",
        "IOMediaBSDClient",
        "IOPartitionScheme",
        "IOStorage",
        
        // Memory/VM
        "IOVMPage",
        "IOVMPageUserClient",
        "IOMemoryDescriptor",
        "IOMemoryDescriptorUserClient",
        
        // Network
        "IONetworkInterface",
        "IONetworkController",
        "IOEthernetInterface",
        "IOEthernetController",
        "IO80211Controller",
        "IO80211Interface",
        
        // HID
        "IOHIDDevice",
        "IOHIDEventService",
        "IOHIDUserClient",
        
        // Graphics
        "IOGraphicsDevice",
        "IOGraphicsAccelerator",
        "IODisplayDevice",
        
        // USB
        "IOUSBDevice",
        "IOUSBHostDevice",
        "IOUSBHostInterface",
        
        // Bluetooth
        "IOBluetoothDevice",
        "IOBluetoothHostController",
        
        // Audio
        "IOAudioDevice",
        "IOAudioEngine",
        "IOAudioStream",
        
        // Power
        "IOPowerDevice",
        "IOPowerConnection",
        
        // System
        "IOPlatformDevice",
        "IOPlatformExpert",
        "IOCPU",
        "IOCPUThermal",
        
        // Security/Crypto
        "IOCryptoAccelerator",
        "IOCryptoUserClient",
        "IOAESAccelerator",
        "IOAESHardwareAccelerator",
        
        // Misc
        "IOSerialBSDClient",
        "IOSerialStreamSync",
        "IOTTYDevice",
        "IOPPPDevice",
        "IOWatchDogTimer",
        "IOTimerEventSource",
        "IOInterruptEventSource",
        "IOCommandGate",
        "IOWorkLoop",
        "IOEventSource",
        "IOService",
        "IORegistryEntry",
        "IONotifier",
        "IOIterator",
        "IOCatalogue",
        "IOResources",
        "IOUserClient",
        "IOUserServer",
        "IOKernelUserClient",
        "IOKernelUserServer",
        
        // Add more as needed
        NULL
    };
    
    log_msg("%-50s | %-15s | %s\n", "SERVICE NAME", "STATUS", "NOTES");
    log_msg("---------------------------------------------------------------------------------------------------\n");
    
    for (int i = 0; services[i] != NULL; i++) {
        g_total_count++;
        int result = test_service(services[i]);
        
        if (result == 1) {
            g_openable_count++;
            log_msg("%-50s | [+] OPEN        | POTENTIAL CWE-862!\n", services[i]);
        } else if (result == 0) {
            g_blocked_count++;
            log_msg("%-50s | [-] BLOCKED     | Sandbox/MACF denied\n", services[i]);
        } else {
            log_msg("%-50s | [?] %-11s | %s\n", services[i], "ERROR", get_error_string(result));
        }
        
        // Small delay to prevent watchdog
        usleep(1000);
    }
    
    log_msg("\n=== Summary ===\n");
    log_msg("Total tested: %d\n", g_total_count);
    log_msg("Openable (CWE-862 candidates): %d\n", g_openable_count);
    log_msg("Blocked by sandbox: %d\n", g_blocked_count);
    log_msg("Not found: %d\n", g_total_count - g_openable_count - g_blocked_count);
    
    if (g_openable_count > 0) {
        log_msg("\n!!! FOUND %d POTENTIAL CWE-862 TARGETS !!!\n", g_openable_count);
        log_msg("Next step: fuzz selectors on openable services\n");
    } else {
        log_msg("\nNo openable services found. Need broader enumeration.\n");
    }
    
    fclose(g_log);
    return 0;
}
