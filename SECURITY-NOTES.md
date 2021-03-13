# Security notes

Since `matchhostfsowner` is supposed to run as setuid root, it should be very careful lest it introduces security vulnerabilities.

Do not trust any user input. This does not only mean data read via stdin, but also environment variables and command line arguments. In particular, environment variables and CLI arguments can refer to arbitrary files. Here are some known caveats:

 * The referenced file may be one that the caller should not have access to. If you read it, don't log its contents, or you'll risk an arbitrary file content leak vulnerability. If you write to it or delete it, be careful that the caller can't abuse this behavior to overwrite/delete arbitrary files.
 * The referenced file may be malicious input. If you parse it, be careful that your parser doesn't have vulnerabilities.
 * The referenced file may be a symlink, which can be abused for TOCTU attacks. For example, say that before you open a file, you check whether the caller may access the file. But if, right after the time when you're done checking and before the time you open the file, the caller deletes the file and replaces it with a symlink, then it can trick you into opening an arbitrary file. You should check permissions *after* having opened a file. Note that `O_NOFOLLOW` is not enough, see the next item.
 * The referenced file may be inside a directory that the caller controls. Even if you solve the previous issue by opening with `O_NOFOLLOW`, the caller can still perform a TOCTU attack by replacing one of the parent directories with a symlink.
 * The referenced file may be a FIFO file. The caller can trick your program into opening a FIFO file that is never opened on the other side, causing your program to get stuck forever. You should open files with `O_NONBLOCK` to defeat this.

Since `matchhostfsowner` is supposed to be used in a container context, we can enforce certain usage styles that are less acceptable outside such a context. For example, we insist on a hardcoded config file location so that callers can't attack us with malicious symlinks or content.
