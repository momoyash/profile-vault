# Move an existing browser profile

Migration requires a closed source browser and a mounted container with enough free space. Use the same browser on the same Windows account and machine. Browser encryption can bind cookies and saved passwords to the application or operating-system account. Verify logins after copying.

1. Open the source profile and visit `brave://version` or `chrome://version`. Record **Profile Path**. The final directory might be `Default` or `Profile 1`.
2. Close all windows of that browser, including the protected session. Wait for its launcher to exit.
3. Mount the container in VeraCrypt. Record the drive letter.
4. Inside the container, create `Brave User Data` or `Chrome User Data`. If the destination already contains a profile, back up the container before changing it.
5. Copy the source profile directory into that user data directory, keeping its directory name.
6. Copy `Local State` from the source profile's parent directory to the new user data directory. It contains browser encryption state. In its JSON `profile` object, keep only the selected profile's entry in `info_cache`, set `last_used` to its directory name, and set `last_active_profiles` to an array containing that directory name.
7. Compare source and copied file hashes while both browsers are closed. Dismount the volume.
8. Open the protected shortcut. Check history, bookmarks, extensions, saved passwords, and website sessions. Close the protected session and reopen it to check persistence.

After verifying the protected copy and a recovery backup, remove the original profile through the ordinary browser's profile management. The original directory and any backups remain readable until removed. File deletion alone does not guarantee that previous disk contents are unrecoverable.

A container's allocated size limits its capacity. Choose enough room for future browsing data. Use VeraCrypt's volume tools or a new, larger container when growth is needed.
