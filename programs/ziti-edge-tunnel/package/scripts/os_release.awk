#!/usr/bin/awk -f
BEGIN {
    if(ARGC != 2) {
        print "ERROR: Invoke as ./os_release.awk OSRELEASE_VAR_KEY"
        exit 1
    }
    key=ARGV[1]
    ARGV[1] = ""
    FS = "="
    OS_RELEASE="/etc/os-release"

    while((getline < OS_RELEASE) > 0) {
        if (substr($1, 0, 1) != "#") {
            if(tolower(key) == tolower($1)) {
                value = tolower($2)
                gsub(/"/,"",value)
                print value
                exit 0
            }
        }
    }

    if(ERRNO) {
        print "ERROR: Could not open " OS_RELEASE
        exit ERRNO
    }

    print "ERROR: key not found."
    exit 1
}
