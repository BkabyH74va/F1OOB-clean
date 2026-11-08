// minimal_test.mm
// Absolute minimal test to isolate crash cause

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <stdio.h>
#import <unistd.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        // Log to stderr (visible in Console)
        fprintf(stderr, "=== MINIMAL TEST START ===\n");
        fprintf(stderr, "PID: %d\n", getpid());
        
        // Test 1: Just IOKit init
        fprintf(stderr, "Test 1: IOKit init...\n");
        kern_return_t kr = IOMainPort(bootstrap_port, NULL);
        fprintf(stderr, "IOMainPort result: 0x%x\n", kr);
        
        // Test 2: Get matching service (should not crash)
        fprintf(stderr, "Test 2: IOServiceMatching...\n");
        CFMutableDictionaryRef matching = IOServiceMatching("IOService");
        if (matching) {
            fprintf(stderr, "Matching dict created: %p\n", matching);
            CFRelease(matching);
        } else {
            fprintf(stderr, "Matching dict is NULL\n");
        }
        
        // Test 3: Get service (should not crash)
        fprintf(stderr, "Test 3: IOServiceGetMatchingService...\n");
        io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpert"));
        if (service) {
            fprintf(stderr, "Service found: %d\n", service);
            IOObjectRelease(service);
        } else {
            fprintf(stderr, "Service not found (this is OK)\n");
        }
        
        // Test 4: Try to open (should not crash even if blocked)
        fprintf(stderr, "Test 4: IOServiceOpen...\n");
        service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpert"));
        if (service) {
            io_connect_t connect = 0;
            kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
            fprintf(stderr, "IOServiceOpen result: 0x%x\n", kr);
            if (kr == KERN_SUCCESS) {
                IOServiceClose(connect);
                fprintf(stderr, "OPENED SUCCESSFULLY!\n");
            }
            IOObjectRelease(service);
        }
        
        fprintf(stderr, "=== MINIMAL TEST COMPLETE ===\n");
    }
    return 0;
}
