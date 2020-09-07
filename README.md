# USB Log Analyser

A script to pull, process and analyse USB logs on Windows.

Notify yourself by e-mail when an unauthorised USB device has been detected.

## Enable Windows USB logs

Open event Viewer as administrator

Applications and Service Logs > Microsoft > Windows > DriverFrameworks-UserMode > Properties > Enable

## Dependencies

pip install python-evtx

## usb.conf

This is your configuration file.

*general* - Enable script running and define file locations.

*email* - Enable email notifications, define email accounts and SMTP infomation.

*authorised devices* - Define a list of authorised USB devices. You wont be notified about these.

## Task Scheduler

If you want this script to be run periodically, you can add this to your Task Scheduler on Windows.

Run Task Scheduler as Admin and choose when you would like the script to be run. 