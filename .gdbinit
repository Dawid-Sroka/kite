target remote :1234

# mimiker is build in docker
set substitute-path /mimiker /home/user/src/mimiker

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
