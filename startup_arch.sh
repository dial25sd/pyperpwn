pwd=pynetrator

if [ $(systemctl is-active mongodb) == "active" ]
then
	echo "MongoDB is already running"
else
	systemctl start mongodb
	echo "started MongoDB"
fi

if [ $(systemctl is-active postgresql) == "active" ]
then
	echo "PostgreSQL is already running"
else
	systemctl start postgresql
	echo "started PostgreSQL"
fi

echo "Starting MSFRPCD..."
msfrpcd -P $pwd -S -f -a 127.0.0.1
