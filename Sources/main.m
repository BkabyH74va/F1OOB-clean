#import <UIKit/UIKit.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UITextView *logView;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    
    UIViewController *vc = [[UIViewController alloc] init];
    self.logView = [[UITextView alloc] initWithFrame:self.window.bounds];
    self.logView.editable = NO;
    self.logView.text = @"Path Traversal Fuzzer\n\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self fuzz];
    });
    
    return YES;
}

- (void)log:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:[msg stringByAppendingString:@"\n"]];
    });
}

- (void)fuzz {
    [self log:@"[1] Starting path traversal fuzz...\n"];
    
    // Target files outside sandbox
    NSArray *targets = @[
        @"/etc/passwd",
        @"/etc/hosts",
        @"/private/etc/passwd",
        @"/System/Library/CoreServices/SystemVersion.plist",
        @"/usr/lib/libSystem.dylib",
        @"/var/mobile/Library/Preferences/com.apple.springboard.plist",
    ];
    
    // Path traversal patterns
    NSArray *patterns = @[
        @"../../../../../../%@",
        @"..%%2f..%%2f..%%2f..%%2f..%%2f..%%2f%@",
        @"..%2f..%2f..%2f..%2f..%2f..%2f%@",
        @"%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%@",
        @"%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%@",
        @"....//....//....//....//....//....//%@",
        @"..\\..\\..\\..\\..\\..\\%@",
    ];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();
    
    for (NSString *target in targets) {
        [self log:[NSString stringWithFormat:@"[2] Testing target: %@", target]];
        
        for (NSString *pattern in patterns) {
            NSString *traversal = [NSString stringWithFormat:pattern, target];
            NSString *fullPath = [home stringByAppendingPathComponent:traversal];
            
            // Test 1: fileExistsAtPath
            BOOL exists = [fm fileExistsAtPath:fullPath];
            if (exists) {
                [self log:[NSString stringWithFormat:@"  *** fileExistsAtPath SUCCESS: %@ ***", fullPath]];
            }
            
            // Test 2: contentsAtPath
            NSData *data = [fm contentsAtPath:fullPath];
            if (data) {
                [self log:[NSString stringWithFormat:@"  *** contentsAtPath SUCCESS: %@ (%lu bytes) ***", fullPath, (unsigned long)data.length]];
            }
            
            // Test 3: NSURL fileURLWithPath
            NSURL *url = [NSURL fileURLWithPath:fullPath];
            NSData *urlData = [NSData dataWithContentsOfURL:url];
            if (urlData) {
                [self log:[NSString stringWithFormat:@"  *** NSURL SUCCESS: %@ (%lu bytes) ***", fullPath, (unsigned long)urlData.length]];
            }
            
            // Test 4: stringByStandardizingPath
            NSString *resolved = [fullPath stringByStandardizingPath];
            if (![resolved hasPrefix:home]) {
                [self log:[NSString stringWithFormat:@"  *** StandardizingPath ESCAPED: %@ -> %@ ***", fullPath, resolved]];
            }
            
            usleep(10000); // 10ms
        }
    }
    
    [self log:@"\n[3] Fuzz complete"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
