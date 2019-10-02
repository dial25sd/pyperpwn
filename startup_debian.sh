pwd=pynetrator
service mongodb start
service postgresql start
msfrpcd -P $pwd -S -f -a 127.0.0.1
