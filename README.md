# F1OOB - iOS 27.0.1 Sandbox Escape

KAMUI-based sandbox escape for iOS 27.0.1 using containermanagerd symlink vulnerability.

## Target
- Device: iPad A16 (iPad15,8)
- iOS: 27.0.1 (24A446)
- PAC: Enabled
- MTE: Disabled

## Vulnerability
CVE-2026-XXXX: containermanagerd symlink validation bypass

## Escape Strategies
1. Class 13 + partDomain traversal (bad_query successor)
2. Class 7 part-directory symlink
3. Class 13 direct MobileGestalt query
4. Class 12 geod + traversal

## Access Granted
- /var/containers/Data/System
- /var/mobile/Containers/Data/InternalDaemon
- /var/mobile/Library/MobileGestalt (read/write)
- All MCM containers (apps, groups, plugins)

## NOT Included
- Kernel R/W
- Root privileges
- PAC bypass

## Build
1. Add App Group: group.com.jasonquiles.F1OOB
2. Set Code Signing Entitlements to F1OOB.entitlements
3. Build and run on iOS 27.0.1 device

## Credits
- KAMUI: https://github.com/murk-sus/kamui-escape
- worse_query: https://github.com/forcequitOS/worse_query
