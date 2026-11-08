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
    
    NSArray *targets = @[
        @"/etc/passwd",
        @"/etc/hosts",
        @"/private/etc/passwd",
        @"/System/Library/CoreServices/SystemVersion.plist",
    ];
    
    // Use placeholder instead of %@ to avoid format string crashes
    NSArray *patterns = @[
        @"../../../../../../TARGET",
        @"..%%2f..%%2f..%%2f..%%2f..%%2f..%%2fTARGET",
        @"..%2f..%2f..%2f..%2f..%2f..%2fTARGET",
        @"%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/TARGET",
        @"%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/TARGET",
        @"....//....//....//....//....//....//TARGET",
    ];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();
    
    for (NSString *target in targets) {
        NSString *logLine = [@"[2] Testing: " stringByAppendingString:target];
        [self log:logLine];
        
        for (NSString *pattern in patterns) {
            // Use stringByReplacingOccurrencesOfString instead of stringWithFormat:
            NSString *traversal = [pattern stringByReplacingOccurrencesOfString:@"TARGET" withString:target];
            NSString *fullPath = [home stringByAppendingPathComponent:traversal];
            
            // Test 1: fileExistsAtPath
            BOOL exists = [fm fileExistsAtPath:fullPath];
            if (exists) {
                NSString *msg = [@"  *** fileExistsAtPath: " stringByAppendingString:fullPath];
                [self log:msg];
            }
            
            // Test 2: contentsAtPath
            NSData *data = [fm contentsAtPath:fullPath];
            if (data) {
                NSString *msg = [@"  *** contentsAtPath: " stringByAppendingString:fullPath];
                msg = [msg stringByAppendingFormat:@" (%lu bytes)", (unsigned long)data.length];
                [self log:msg];
            }
            
            // Test 3: NSURL
            NSURL *url = [NSURL fileURLWithPath:fullPath];
            NSData *urlData = [NSData dataWithContentsOfURL:url];
            if (urlData) {
                NSString *msg = [@"  *** NSURL: " stringByAppendingString:fullPath];
                msg = [msg stringByAppendingFormat:@" (%lu bytes)", (unsigned long)urlData.length];
                [self log:msg];
            }
            
            // Test 4: stringByStandardizingPath
            NSString *resolved = [fullPath stringByStandardizingPath];
            if (![resolved hasPrefix:home]) {
                NSString *msg = [@"  *** ESCAPED: " stringByAppendingString:resolved];
                [self log:msg];
            }
            
            usleep(10000);
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
