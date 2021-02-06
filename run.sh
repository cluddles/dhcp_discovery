# Not 100% sure this is correct, but it might work...
rm -f discovery.out.bak
mv discovery.out discovery.out.bak
nohup ./discovery.py >> discovery.out 2>&1
