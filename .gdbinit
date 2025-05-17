target remote :1234

# replace /home/user/src/mimiker with path to mimiker sources
set substitute-path /mimiker /home/user/src/mimiker
set substitute-path /home/runner/work/kite-binaries-builder/kite-binaries-builder/mimiker /home/user/src/mimiker

# Load breakpoints automatically on startup
source breakpoints.txt

# Define the actions to take when SIGTERM is caught
define hook-stop
    # Save breakpoints to the file if there are any
    !echo "" > breakpoints.txt
    save breakpoints breakpoints.txt
end

define hook-continue
    # Save breakpoints to the file if there are any
    !echo "" > breakpoints.txt
    save breakpoints breakpoints.txt
end

define hook-break
    # Save breakpoints to the file if there are any
    !echo "" > breakpoints.txt
    save breakpoints breakpoints.txt
end

define hook-next
    # Save breakpoints to the file if there are any
    !echo "" > breakpoints.txt
    save breakpoints breakpoints.txt
end

la sr
