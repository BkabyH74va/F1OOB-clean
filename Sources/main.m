#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <sys/utsname.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UITextView *logView;
- (void)log:(NSString *)msg;
@end

@implementation AppDelegate

- (void)log:(NSString *)msg {
    NSString *timestamp = [NSDateFormatter localizedStringFromDate:[NSDate date] dateStyle:NSDateFormatterNoStyle timeStyle:NSDateFormatterMediumStyle];
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", timestamp, msg];
    NSLog(@"%@", line);
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:line];
    });
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor whiteColor];
    
    UIViewController *vc = [[UIViewController alloc] init];
    self.logView = [[UITextView alloc] initWithFrame:self.window.bounds];
    self.logView.editable = NO;
    self.logView.font = [UIFont monospaceSystemFontOfSize:12];
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    [self log:@"=== F1OOB DIAGNOSTIC START ==="];
    
    // Device info
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s", uts.machine]];
    [self log:[NSString stringWithFormat:@"iOS: %@", [[UIDevice currentDevice] systemVersion]]];
    
    // Test 1: Metal
    [self log:@"TEST 1: Metal device..."];
    id<MTLDevice> dev = ltc1qalrd99hju33uagsf8927k7xfxr423gr93gnjz8();
    if (dev) {
        [self log:[NSString stringWithFormat:@"PASS: Metal device = %@", dev.name]];
    } else {
        [self log:@"FAIL: No Metal device"];
    }
    
    // Test 2: IOSurfaceRoot access
    [self log:@"TEST 2: IOSurfaceRoot..."];
    io_service_t iosurface_root = IOServiceGetMatchingService(0, IOServiceMatching("IOSurfaceRoot"));
    if (iosurface_root) {
        [self log:[NSString stringWithFormat:@"PASS: IOSurfaceRoot = 0x%x", iosurface_root]];
        IOObjectRelease(iosurface_root);
    } else {
        [self log:@"FAIL: IOSurfaceRoot not found (sandbox?)"];
    }
    
    // Test 3: AGX access
    [self log:@"TEST 3: AGXAccelerator..."];
    io_service_t agx = IOServiceGetMatchingService(0, IOServiceMatching("AGXAcceleratorG16P"));
    if (!agx) agx = IOServiceGetMatchingService(0, IOServiceMatching("AGXAcceleratorG18P"));
    if (!agx) agx = IOServiceGetMatchingService(0, IOServiceMatching("AGXAcceleratorG14P"));
    if (agx) {
        [self log:[NSString stringWithFormat:@"PASS: AGX = 0x%x", agx]];
        IOObjectRelease(agx);
    } else {
        [self log:@"FAIL: AGX not found (sandbox?)"];
    }
    
    // Test 4: Memory allocation
    [self log:@"TEST 4: posix_memalign..."];
    void *test_buf = NULL;
    int ret = posix_memalign(&test_buf, 4096, 0x10000);
    if (ret == 0 && test_buf) {
        [self log:@"PASS: posix_memalign succeeded"];
        memset(test_buf, 0x41, 0x10000);
        [self log:@"PASS: memset succeeded"];
        free(test_buf);
    } else {
        [self log:[NSString stringWithFormat:@"FAIL: posix_memalign returned %d", ret]];
    }
    
    // Test 5: Metal buffer
    [self log:@"TEST 5: Metal buffer..."];
    if (dev) {
        void *buf_mem = NULL;
        if (posix_memalign(&buf_mem, 4096, 0x10000) == 0) {
            memset(buf_mem, 0x41, 0x10000);
            id<MTLBuffer> buf = [dev newBufferWithBytesNoCopy:buf_mem
                                                       length:0x10000
                                                      options:MTLResourceStorageModeShared
                                                  deallocator:nil];
            if (buf) {
                [self log:[NSString stringWithFormat:@"PASS: Metal buffer created, GPU addr = 0x%llx", (uint64_t)buf.gpuAddress]];
            } else {
                [self log:@"FAIL: newBufferWithBytesNoCopy returned nil"];
            }
        }
    }
    
    [self log:@"=== DIAGNOSTIC COMPLETE ==="];
    [self log:@"If all PASS, exploit code can be added back"];
    
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
