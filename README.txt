# 3heroes
sudo apt-get update
sudo install git python3 mysql-server
git clone https://github.com/thanhdevil9699/3heroes.git

Cai dat MySQL:
sudo mysql_secure_installation
sudo mysql
SELECT user,authentication_string,plugin,host FROM mysql.user;
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '09061999';
FLUSH PRIVILEGES;

Mo Terminal o thu muc vua clone:
python3 -m venv venv
source venv/bin/activate
pip3 install --upgrade pip setuptools wheel
pip3 install -r requirements.txt
python3 run.py

Mo MySQL o thu muc vua clone:
mysql -u root -p
source database.sql
