#!/bin/sh
xcrun -sdk iphoneos cc -Wall -arch arm64 -arch arm64e *.c *.m -o nvnonce -framework IOKit -framework CoreFoundation -framework Foundation -l MobileGestalt
#./jtool --sign --inplace --ent ent.plist nvnonce
#./jtool --sign --inplace nvnonce
ldid -Sent.plist nvnonce
chown 0:0 nvnonce
chmod u+s nvnonce

