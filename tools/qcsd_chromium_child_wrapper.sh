#!/bin/sh
exec /opt/qcsd-playwright/chromium-1200/chrome-linux/chrome --disable-crashpad-for-testing "$@"
