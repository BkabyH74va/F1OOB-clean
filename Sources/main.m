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
    
    [self log:@"=== IOSurface Kernel Error Trigger ==="];
    
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s | iOS: %@", uts.machine, [[UIDevice currentDevice] systemVersion]]];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self triggerIOSSurfaceErrors];
    });
    
    return YES;
}

- (void)triggerIOSSurfaceErrors {
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
    
    // Step 2: Try to create surface with ID 0 (should trigger kernel error)
    [self log:@"[2] Creating surface with properties designed to trigger kernel error..."];
    
    // Craft properties that might cause SID: 0x0 error
    NSDictionary *props = @{
        @"IOSurfaceIsGlobal": @YES,
        @"IOSurfaceWidth": @256,
        @"IOSurfaceHeight": @256,
        @"IOSurfaceAllocSize": @65536,
        @"IOSurfacePixelFormat": @1111970369,
        // Try to trigger the buffer: 0x0 error
        @"IOSurfaceAddress": @0,
        @"IOSurfaceOffset": @0,
    };
    
    uint32_t surface_id = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0,
        (__bridge CFDictionaryRef)props, sizeof(props),
        NULL, NULL, &surface_id, NULL);
    
    [self log:[NSString stringWithFormat:@"Surface create result: 0x%x (ID: %u)", kr, surface_id]];
    
    // Step 3: Try multiple variations to trigger different kernel errors
    [self log:@"[3] Trying variations to trigger kernel errors..."];
    
    // Variation 1: Minimal properties
    NSDictionary *minimal = @{
        @"IOSurfaceWidth": @1,
        @"IOSurfaceHeight": @1,
        @"IOSurfaceAllocSize": @1,
    };
    uint32_t sid1 = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0,
        (__bridge CFDictionaryRef)minimal, sizeof(minimal),
        NULL, NULL, &sid1, NULL);
    [self log:[NSString stringWithFormat:@"Minimal surface: 0x%x (ID: %u)", kr, sid1]];
    
    // Variation 2: Large dimensions (potential integer overflow)
    NSDictionary *large = @{
        @"IOSurfaceWidth": @0x10000,
        @"IOSurfaceHeight": @0x10000,
        @"IOSurfaceAllocSize": @0x10000000,
    };
    uint32_t sid2 = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0,
        (__bridge CFDictionaryRef)large, sizeof(large),
        NULL, NULL, &sid2, NULL);
    [self log:[NSString stringWithFormat:@"Large surface: 0x%x (ID: %u)", kr, sid2]];
    
    // Variation 3: Zero dimensions
    NSDictionary *zero = @{
        @"IOSurfaceWidth": @0,
        @"IOSurfaceHeight": @0,
        @"IOSurfaceAllocSize": @0,
    };
    uint32_t sid3 = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0,
        (__bridge CFDictionaryRef)zero, sizeof(zero),
        NULL, NULL, &sid3, NULL);
    [self log:[NSString stringWithFormat:@"Zero surface: 0x%x (ID: %u)", kr, sid3]];
    
    // Step 4: Try to use surface ID 0 directly (trigger the kernel error we saw)
    [self log:@"[4] Attempting to use surface ID 0..."];
    
    // Try to lock surface ID 0
    uint32_t seed = 0;
    kr = IOConnectCallMethod(conn, 1, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
    [self log:[NSString stringWithFormat:@"Lock surface 0: 0x%x", kr]];
    
    // Step 5: Check if we can trigger the fClientTask error
    [self log:@"[5] Testing fClientTask validation..."];
    
    // Create a surface, then try to access it from a different "task" context
    if (surface_id > 0) {
        [self log:[NSString stringWithFormat:@"Created surface ID %u, testing access...", surface_id]];
        
        // Try to get base address
        void *base = NULL;
        kr = IOConnectCallMethod(conn, 2, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        [self log:[NSString stringWithFormat:@"Get base address: 0x%x", kr]];
    }
    
    IOServiceClose(conn);
    [self log:@"=== Trigger Complete ==="];
    [self log:@"Check Console for kernel(IOSurface) errors"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
