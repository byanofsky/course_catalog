apt-get -qqy update
apt-get -qqy install apache2
apt-get install libapache2-mod-wsgi
a2enmod wsgi
apt-get -qqy install python-pip
