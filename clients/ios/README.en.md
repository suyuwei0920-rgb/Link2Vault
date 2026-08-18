# iPhone Shortcut (Experimental)

The public repository does not ship an unsigned `.shortcut` bundle. Apple
Shortcuts/iCloud must create and sign that bundle. Build the actions described
in the Chinese setup guide, entering your own HTTPS server and one-time enrollment
code during setup. Store the resulting device token locally and send it only in
the Authorization header.
