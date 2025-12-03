This Linux Security Logger is a real-time monitoring tool that tracks both authentication activity and file-system changes to identify potential security risks. 
It continuously listens to system authentication logs using journalctl, detecting events such as failed login attempts, incorrect sudo passwords, user authentication 
failures, and root session openings. Simultaneously, it monitors a chosen directory using the watchdog library to record file creations, deletions, modifications, and movements.
By combining login monitoring with file-system surveillance, the tool provides a comprehensive security overview that helps detect unauthorized access attempts and suspicious file activity in real time.
