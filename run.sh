# This seems to do the job
# Make sure you've cd-ed into the relevant discovery dir

# Backup last output (and remove the previous backup)
rm -f discovery.out.bak
mv discovery.out discovery.out.bak
# Run with nohup so it won't die if the terminal closes etc
nohup sudo ./discovery.py >> discovery.out 2>&1 &
