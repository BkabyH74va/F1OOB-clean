# F1OOB iPad A16

IOSurface F1 wrap -> GPU cross-object OOB write for iPad A16 (no MTE)

## Structure

- `Sources/main.m` — exploit code with runtime IOSurface loading
- `Sources/Info.plist` — app config for iPad
- `.github/workflows/build-ipa.yml` — build script with IOKit framework

## Build

Push to trigger GitHub Actions build.

## Target

- Device: iPad A16 (iPad15,8)
- iOS: 27.0.1 (24A446)
- GPU: AGXAcceleratorG16P
