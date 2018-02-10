#!/bin/sh
xcrun -sdk iphoneos cc -Wall -arch arm64 *.c -o nvnonce -framework IOKit -framework CoreFoundation
./jtool --sign --inplace --ent ent.plist nvnonce

