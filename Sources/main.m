#import <UIKit/UIKit.h>
#import <Metal/Metal.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];

    UIViewController *viewController = [[UIViewController alloc] init];
    viewController.view.backgroundColor = [UIColor systemBackgroundColor];

    UILabel *titleLabel = [[UILabel alloc] init];
    titleLabel.text = @"Device Diagnostics";
    titleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleLargeTitle];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;

    id<MTLDevice> metalDevice = MTLCreateSystemDefaultDevice();
    NSString *metalName = metalDevice ? metalDevice.name : @"Not available";
    NSString *details = [NSString stringWithFormat:
        @"Model: %@\nSystem: %@\nMetal: %@",
        UIDevice.currentDevice.model,
        UIDevice.currentDevice.systemVersion,
        metalName];

    UILabel *detailsLabel = [[UILabel alloc] init];
    detailsLabel.text = details;
    detailsLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    detailsLabel.textAlignment = NSTextAlignmentCenter;
    detailsLabel.numberOfLines = 0;
    detailsLabel.translatesAutoresizingMaskIntoConstraints = NO;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[titleLabel, detailsLabel]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 24;
    stack.alignment = UIStackViewAlignmentFill;
    stack.translatesAutoresizingMaskIntoConstraints = NO;

    [viewController.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:viewController.view.safeAreaLayoutGuide.leadingAnchor constant:24],
        [stack.trailingAnchor constraintEqualToAnchor:viewController.view.safeAreaLayoutGuide.trailingAnchor constant:-24],
        [stack.centerYAnchor constraintEqualToAnchor:viewController.view.safeAreaLayoutGuide.centerYAnchor]
    ]];

    self.window.rootViewController = viewController;
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
