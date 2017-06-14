apt-get -qqy update
apt-get -qqy install apache2
apt-get -qqy install libapache2-mod-wsgi
apt-get -y install python-pip
apt-get -y install postgresql
#
sudo -u postgres createuser --no-createdb --encrypted course_catalog
sudo -u postgres createdb course_catalog

pip install virtualenv
cd /var/www/html/course_catalog
virtualenv venv
source venv/bin/activate 
